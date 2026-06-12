"""Proving battery for the concrete WORM sink adapters.

What is demonstrated, end to end and offline:
  1. HTTPSink delivers every audit line to an HTTP collector (in-process
     http.server standing in for the append-only API) and the delivered
     copy is a verifiable hash chain on its own.
  2. SyslogSink frames each line as RFC 3164 and a UDP listener receives it.
  3. FileSink + AuditLog.sinks: local log destroyed, sink copy survives and
     still verifies — the mirror story, through the adapter interface.
  4. strict_sinks: with the collector down, the ENGINE fails closed
     (ENGINE-AUDIT-UNAVAILABLE) — no record, no decision.
  5. S3ObjectLockSink without boto3 fails loudly at construction (config
     error), and with a stub client writes object-per-entry WORM keys.

Run:  python -m aegis.worm_sinks_test
"""

from __future__ import annotations

import http.server
import json
import socket
import sys
import tempfile
import threading
from pathlib import Path

from .audit import AuditLog
from .engine import Engine
from .model import Action, Effect
from .worm_sinks import FileSink, HTTPSink, S3ObjectLockSink, SinkError, SyslogSink

_checks: list[tuple[str, bool]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    _checks.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))


def _policy() -> dict:
    return {"enabled_packs": ["destructive_ops"], "destructive": {"effect": "block"}}


def _collector() -> tuple[http.server.HTTPServer, list[str]]:
    received: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("content-length", 0)))
            received.append(body.decode("utf-8"))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, received


def run() -> int:
    print("=== WORM sink adapters ===\n")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_worm_"))

    # 1. HTTP delivery + chain verifies off-host
    srv, received = _collector()
    url = f"http://127.0.0.1:{srv.server_port}/append"
    audit = AuditLog(tmp / "local.jsonl", sinks=[HTTPSink(url)])
    eng = Engine(_policy(), audit=audit)
    eng.evaluate(Action(tool="Bash", tool_input={"command": "ls"}))
    eng.evaluate(Action(tool="Bash", tool_input={"command": "rm -rf /data"}))
    check("HTTP sink received every entry", len(received) == 2)
    remote = AuditLog(tmp / "remote.jsonl")
    remote.path.write_text("\n".join(received) + "\n", encoding="utf-8")
    ok, n, err = remote.verify()
    check("delivered copy is a valid chain on its own", ok and n == 2, err or f"{n} entries")
    check("no sink errors recorded", not audit.sink_errors)

    # 2. syslog framing over UDP
    lsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    lsock.bind(("127.0.0.1", 0))
    lsock.settimeout(3)
    sys_audit = AuditLog(tmp / "sys.jsonl",
                         sinks=[SyslogSink("127.0.0.1", lsock.getsockname()[1])])
    Engine(_policy(), audit=sys_audit).evaluate(
        Action(tool="Bash", tool_input={"command": "cat x"}))
    datagram = lsock.recv(65535).decode("utf-8")
    check("syslog datagram received with RFC3164 frame",
          datagram.startswith("<") and "aegis-audit: " in datagram)
    payload = datagram.split("aegis-audit: ", 1)[1]
    check("syslog payload is the audit JSON line",
          json.loads(payload).get("seq") == 0)
    lsock.close()

    # 3. local log destroyed, FileSink copy survives + verifies
    worm = tmp / "worm-mount" / "audit.jsonl"
    fa = AuditLog(tmp / "doomed.jsonl", sinks=[FileSink(worm)])
    e3 = Engine(_policy(), audit=fa)
    e3.evaluate(Action(tool="Bash", tool_input={"command": "ls"}))
    e3.evaluate(Action(tool="Bash", tool_input={"command": "rm -rf /x"}))
    (tmp / "doomed.jsonl").unlink()  # attacker destroys the local log
    surv = AuditLog(worm)
    ok, n, err = surv.verify()
    check("sink copy survives local destruction and verifies", ok and n == 2,
          err or f"{n} entries")

    # 4. strict sinks: collector down => engine fails closed
    srv.shutdown()
    strict = AuditLog(tmp / "strict.jsonl", sinks=[HTTPSink(url, timeout=1.0)],
                      strict_sinks=True)
    d = Engine(_policy(), audit=strict).evaluate(
        Action(tool="Bash", tool_input={"command": "ls"}))
    check("strict sink down => decision BLOCKED (no record, no decision)",
          d.effect is Effect.BLOCK
          and any(f.rule_id == "ENGINE-AUDIT-UNAVAILABLE" for f in d.findings))

    # lenient default: same outage only counts an error, gate still decides
    lenient = AuditLog(tmp / "lenient.jsonl", sinks=[HTTPSink(url, timeout=1.0)])
    d2 = Engine(_policy(), audit=lenient).evaluate(
        Action(tool="Bash", tool_input={"command": "ls"}))
    check("lenient sink down => gate still decides, error counted",
          d2.effect is Effect.ALLOW and len(lenient.sink_errors) == 1)

    # 5. S3 sink: loud config failure without boto3; WORM keys with a stub
    try:
        import boto3  # noqa: F401
        have_boto3 = True
    except ImportError:
        have_boto3 = False
    if not have_boto3:
        try:
            S3ObjectLockSink("bucket")
            check("S3 sink without boto3 fails at construction", False)
        except SinkError:
            check("S3 sink without boto3 fails at construction", True)

    puts: list[dict] = []

    class StubS3:
        def put_object(self, **kw):
            puts.append(kw)

    s3 = S3ObjectLockSink("bkt", prefix="audit/", retention_days=365, client=StubS3())
    line = json.dumps({"seq": 7, "entry_hash": "ab" * 32})
    s3.append(line)
    check("S3 sink writes object-per-entry with seq-ordered key",
          puts and puts[0]["Key"].startswith("audit/000000000007-")
          and puts[0]["ObjectLockMode"] == "COMPLIANCE")

    failed = [n for n, ok in _checks if not ok]
    print(f"\n{'PASS' if not failed else 'FAIL'} — {len(_checks) - len(failed)}/{len(_checks)} checks")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(run())
