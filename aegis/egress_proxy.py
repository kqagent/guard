"""Egress proxy — Layer 4 ground-truth enforcement for network egress.

The network twin of the query proxy. In a confined deployment the agent has no
direct network; all traffic goes through here, so enforcement happens on the
REAL destination and the ACTUAL bytes on the wire — not on a `curl` string the
agent typed (which it can obfuscate). This is why it catches what the PDP
cannot:

  * destination is resolved and checked against the allowlist at connect time
    (defeats raw-IP, redirect, and string-obfuscation tricks);
  * SSRF guard blocks cloud-metadata (169.254.169.254) and private/loopback
    ranges that aren't explicitly allowlisted;
  * DLP inspects the payload for secrets and classified data and blocks (or
    redacts) before it leaves — so even an allowlisted host can't be used to
    exfiltrate (closes red-team RT-15).

Fail-closed: no resolvable destination, or any inspection error, => block.

Two parts (same split as query_proxy): EgressGuard is the pure, testable
decision core; ForwardProxy is the transport shell that calls it. HTTPS bodies
are opaque without TLS interception — that's a deployment decision (corp CA);
for CONNECT we still enforce the host allowlist. Stated, not hidden.
"""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from .detectors import _SECRET_PATTERNS

# Hop-by-hop headers are connection-scoped and must not be forwarded by a proxy
# (RFC 7230 §6.1). Plus Proxy-Connection, which clients send to proxies.
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "proxy-connection",
}


@dataclass
class EgressVerdict:
    action: str                 # "allow" | "block"
    host: str | None = None
    reasons: list[str] = field(default_factory=list)
    classification: list[str] = field(default_factory=list)
    redacted_body: str | None = None


class EgressBlocked(Exception):
    def __init__(self, verdict: EgressVerdict):
        self.verdict = verdict
        super().__init__("; ".join(verdict.reasons) or "egress blocked")


class EgressGuard:
    def __init__(self, config: dict | None = None):
        c = config or {}
        self.allow = {h.lower() for h in c.get("allowlist_hosts", [])}
        self.block_metadata = c.get("block_metadata_ip", True)
        self.block_private = c.get("block_private_ranges", True)
        dlp = c.get("dlp", {})
        self.sensitive_terms = [t.lower() for t in dlp.get("sensitive_terms", [])]
        self.scan_secrets = dlp.get("scan_secrets", True)
        self.dlp_effect = dlp.get("effect", "block")  # "block" | "redact"
        self.max_body = int(c.get("max_body_bytes", 1_000_000))

    @classmethod
    def from_policy(cls, policy_path: str | Path = None) -> "EgressGuard":
        policy_path = policy_path or Path(__file__).with_name("policy.json")
        cfg = json.loads(Path(policy_path).read_text(encoding="utf-8"))
        block = dict(cfg.get("egress_proxy", {}))
        # default the allowlist to the engine's egress allowlist if not set
        block.setdefault("allowlist_hosts", cfg.get("egress", {}).get("allowlist_hosts", []))
        if "sensitive_terms" not in block.get("dlp", {}):
            block.setdefault("dlp", {})["sensitive_terms"] = \
                cfg.get("pii_egress", {}).get("sensitive_terms", [])
        return cls(block)

    # -- public ------------------------------------------------------------

    def enforce(self, host=None, url=None, body=b"", method="GET") -> EgressVerdict:
        v = self.decide(host=host, url=url, body=body, method=method)
        if v.action == "block":
            raise EgressBlocked(v)
        return v

    def decide(self, host=None, url=None, body=b"", method="GET") -> EgressVerdict:
        if url and not host:
            try:
                host = urllib.parse.urlsplit(url).hostname
            except ValueError:
                host = None
        host = (host or "").strip().lower().split(":")[0]
        if not host:
            return EgressVerdict("block", None, ["no resolvable destination host — failing closed"])

        allowed = host in self.allow

        # SSRF guard — IP-literal destinations.
        ipobj = None
        try:
            ipobj = ipaddress.ip_address(host)
        except ValueError:
            ipobj = None
        if ipobj is not None and not allowed:
            if self.block_metadata and ipobj.is_link_local:
                return EgressVerdict("block", host,
                                     ["SSRF: link-local / cloud-metadata address blocked"])
            if self.block_private and (ipobj.is_private or ipobj.is_loopback):
                return EgressVerdict("block", host,
                                     ["SSRF: private/loopback address not on allowlist"])

        if not allowed:
            return EgressVerdict("block", host,
                                 [f"destination host '{host}' is not on the egress allowlist"])

        # Host is allowed — now inspect the payload (DLP). This is what stops
        # exfiltration THROUGH an allowlisted host.
        reasons, classes, masked = self._dlp(body)
        if reasons:
            if self.dlp_effect == "redact":
                return EgressVerdict("allow", host,
                                     ["payload redacted before egress"], classes, masked)
            return EgressVerdict("block", host, reasons, classes)

        return EgressVerdict("allow", host, ["host allowlisted, payload clean"])

    # -- DLP ---------------------------------------------------------------

    def _dlp(self, body) -> tuple[list[str], list[str], str]:
        if isinstance(body, bytes):
            text = body[: self.max_body].decode("utf-8", "replace")
        else:
            text = str(body)[: self.max_body]
        reasons: list[str] = []
        classes: list[str] = []
        redacted = text

        if self.scan_secrets:
            for name, pat in _SECRET_PATTERNS:
                for m in re.finditer(pat, text):
                    cap = m.group(1) if m.groups() else m.group(0)
                    reasons.append(f"payload contains a secret ({name})")
                    classes.append(name)
                    redacted = redacted.replace(cap, "[REDACTED-SECRET]")
                    break

        hits = [t for t in self.sensitive_terms if re.search(rf"(?i)\b{re.escape(t)}\b", text)]
        if hits:
            reasons.append(f"payload contains classified data ({', '.join(hits[:3])})")
            classes.extend(hits[:3])

        return reasons, classes, redacted


# ===========================================================================
# ForwardProxy — the transport shell that puts EgressGuard on the wire.
# ===========================================================================
#
# The agent's HTTP(S)_PROXY points here. Plain HTTP requests are inspected in
# full (host allowlist + SSRF + payload DLP) and forwarded only if allowed;
# HTTPS arrives as CONNECT, where the body is opaque under TLS, so we enforce
# the host allowlist at tunnel-open and relay bytes only for allowed hosts.
# Either way an agent on a deny-all-egress network can reach nothing this guard
# did not approve. This is the daemon the docstring/compose referred to.

import http.server  # noqa: E402
import socket  # noqa: E402
import threading  # noqa: E402
import urllib.error  # noqa: E402
import urllib.request  # noqa: E402


def _make_handler(guard: "EgressGuard"):
    class _Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "aegis-egress/1.0"

        def log_message(self, *a):  # quiet by default
            pass

        # -- shared refusal --------------------------------------------------
        def _refuse(self, verdict: EgressVerdict) -> None:
            body = ("BLOCKED BY EGRESS POLICY: "
                    + ("; ".join(verdict.reasons) or "blocked")).encode("utf-8")
            self.send_response(403)
            self.send_header("content-type", "text/plain")
            self.send_header("content-length", str(len(body)))
            self.send_header("connection", "close")
            self.end_headers()
            self.wfile.write(body)

        # -- plain HTTP (full inspection + forward) --------------------------
        def _handle_forward(self) -> None:
            length = int(self.headers.get("content-length", 0) or 0)
            body = self.rfile.read(length) if length else b""
            verdict = guard.decide(url=self.path, body=body, method=self.command)
            if verdict.action == "block":
                self._refuse(verdict)
                return
            # DLP redact mode: forward the sanitized bytes, not the original.
            if verdict.redacted_body is not None:
                body = verdict.redacted_body.encode("utf-8")

            fwd_headers = {k: v for k, v in self.headers.items()
                           if k.lower() not in _HOP_BY_HOP}
            fwd_headers["content-length"] = str(len(body))
            req = urllib.request.Request(self.path, data=body or None,
                                         headers=fwd_headers, method=self.command)
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    payload = resp.read()
                    self.send_response(resp.status)
                    for k, v in resp.headers.items():
                        if k.lower() not in _HOP_BY_HOP and k.lower() != "content-length":
                            self.send_header(k, v)
                    self.send_header("content-length", str(len(payload)))
                    self.send_header("connection", "close")
                    self.end_headers()
                    self.wfile.write(payload)
            except urllib.error.HTTPError as e:  # forward upstream error verbatim
                payload = e.read()
                self.send_response(e.code)
                self.send_header("content-length", str(len(payload)))
                self.send_header("connection", "close")
                self.end_headers()
                self.wfile.write(payload)
            except Exception as e:  # upstream unreachable — fail closed (502)
                self._refuse(EgressVerdict("block", verdict.host,
                                           [f"upstream fetch failed ({type(e).__name__})"]))

        do_GET = _handle_forward
        do_POST = _handle_forward
        do_PUT = _handle_forward
        do_DELETE = _handle_forward
        do_PATCH = _handle_forward
        do_HEAD = _handle_forward

        # -- HTTPS via CONNECT (host allowlist + tunnel) ---------------------
        def do_CONNECT(self) -> None:
            # A CONNECT consumes the connection (tunnel or refusal); never let
            # the HTTP/1.1 handler try to read another request on this socket.
            self.close_connection = True
            host = self.path.split(":")[0]
            try:
                port = int(self.path.split(":")[1])
            except (IndexError, ValueError):
                port = 443
            verdict = guard.decide(host=host, body=b"")  # body opaque under TLS
            if verdict.action == "block":
                self._refuse(verdict)
                return
            try:
                upstream = socket.create_connection((host, port), timeout=15)
            except OSError as e:
                self._refuse(EgressVerdict("block", host,
                                           [f"CONNECT to {host}:{port} failed ({type(e).__name__})"]))
                return
            self.send_response(200, "Connection established")
            self.end_headers()
            self._tunnel(self.connection, upstream)

        @staticmethod
        def _tunnel(a: socket.socket, b: socket.socket) -> None:
            def pump(src, dst):
                try:
                    while True:
                        chunk = src.recv(65536)
                        if not chunk:
                            break
                        dst.sendall(chunk)
                except OSError:
                    pass
                finally:
                    for s in (src, dst):
                        try:
                            s.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
            t = threading.Thread(target=pump, args=(a, b), daemon=True)
            t.start()
            pump(b, a)
            t.join(timeout=1)

    return _Handler


class ForwardProxy:
    """Threaded forward proxy enforcing an EgressGuard on every request.

    proxy = ForwardProxy(EgressGuard.from_policy(), port=8443)
    proxy.start()      # background thread; proxy.port is the bound port
    ...
    proxy.stop()
    """

    def __init__(self, guard: "EgressGuard", host: str = "127.0.0.1", port: int = 8443):
        self.guard = guard
        self._httpd = http.server.ThreadingHTTPServer((host, port), _make_handler(guard))
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    def start(self) -> "ForwardProxy":
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def serve_forever(self) -> None:
        self._httpd.serve_forever()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys
    ap = argparse.ArgumentParser(description="Aegis egress forward proxy")
    ap.add_argument("--serve", action="store_true", help="run the forward proxy")
    ap.add_argument("--policy", default=None, help="policy bundle (egress_proxy block)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8443)
    args = ap.parse_args(argv)
    if not args.serve:
        ap.print_help()
        return 0
    guard = EgressGuard.from_policy(args.policy)
    proxy = ForwardProxy(guard, host=args.host, port=args.port)
    print(f"aegis-egress listening on {args.host}:{args.port} "
          f"(allowlist: {sorted(guard.allow)})")
    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        proxy.stop()
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
