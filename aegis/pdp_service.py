"""Out-of-process Policy Decision Point (PDP) sidecar.

Runs the engine in a separate process at higher privilege than the agent, so
the agent's runtime cannot monkeypatch the decision logic, read the signed
policy, or touch the audit log. The agent (via the broker / Guard) calls it
over loopback HTTP and gets a verdict.

This is the placement the watertight design requires: the thing that decides
must not live inside the thing it governs.

Run as a sidecar:
    python -m aegis.pdp_service --policy aegis/policy.json \
        --audit /var/aegis/audit.jsonl --host 127.0.0.1 --port 8787

Endpoints:
    POST /v1/evaluate  {tool, tool_input, principal?, cwd?} -> Decision JSON
    GET  /healthz      -> "ok"

Audit lives HERE, with the PDP — centralised, off the agent host in prod.
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .engine import Engine
from .model import Action


class _PDPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, engine: Engine):
        super().__init__(addr, handler)
        self.engine = engine


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence default stderr logging
        pass

    def _send(self, code: int, obj) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 (http.server API)
        if self.path == "/healthz":
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802 (http.server API)
        if self.path != "/v1/evaluate":
            self._send(404, {"error": "not found"})
            return
        try:
            n = int(self.headers.get("content-length", 0))
            payload = json.loads(self.rfile.read(n).decode("utf-8"))
            action = Action(
                tool=payload.get("tool", ""),
                tool_input=payload.get("tool_input", {}) or {},
                principal=payload.get("principal"),
                cwd=payload.get("cwd"),
            )
            decision = self.server.engine.evaluate(action)
            self._send(200, decision.to_dict())
        except Exception as e:
            # Client treats any non-200 as fail-closed; still be explicit.
            self._send(500, {"error": f"{type(e).__name__}: {e}"})


def make_server(policy_path, audit_path=None, host="127.0.0.1", port=8787,
                pinned_pubkey=None, signature_path=None, sig_algo=None) -> _PDPServer:
    """Build (but do not start) the PDP server. Port 0 picks a free port;
    read the chosen port from `server.server_address[1]`. When `pinned_pubkey`
    is given, the policy must carry a valid signature or the engine fails
    closed (blocks everything)."""
    engine = Engine.load(policy_path, audit_path=audit_path,
                         pinned_pubkey=pinned_pubkey, signature_path=signature_path,
                         sig_algo=sig_algo)
    return _PDPServer((host, port), _Handler, engine)


def serve(policy_path, audit_path=None, host="127.0.0.1", port=8787,
          pinned_pubkey=None, signature_path=None, sig_algo=None) -> None:
    httpd = make_server(policy_path, audit_path, host, port,
                        pinned_pubkey, signature_path, sig_algo)
    bound = httpd.server_address
    print(f"Aegis PDP listening on http://{bound[0]}:{bound[1]}  (policy={policy_path})")
    if httpd.engine.load_error:
        print(f"WARNING: policy failed to load — PDP will BLOCK everything: {httpd.engine.load_error}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


def main() -> int:
    ap = argparse.ArgumentParser(description="Aegis out-of-process PDP sidecar")
    ap.add_argument("--policy", required=True)
    ap.add_argument("--audit", default=None)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--pubkey", default=None, help="pinned public key (hex); requires a signed policy")
    ap.add_argument("--sig", default=None, help="path to the detached signature (default <policy>.sig)")
    ap.add_argument("--algo", default=None)
    args = ap.parse_args()
    serve(args.policy, args.audit, args.host, args.port,
          pinned_pubkey=args.pubkey, signature_path=args.sig, sig_algo=args.algo)
    return 0


if __name__ == "__main__":
    sys.exit(main())
