"""Stage 3-4 verification (item C) — out-of-process PDP + WORM + fail-closed.

Assumes a PDP is serving the signed FSP bundle with --audit + --sink --strict.
Proves: remote gate decides; decisions mirror to the off-host WORM sink; the audit
chain verifies and ANCHOR-based truncation is detected; and Guard.remote fails
closed when the PDP is unreachable.

    python -m pilot.stage34_verify <pdp_url> <audit_path> <worm_path>
"""
from __future__ import annotations

import sys
from pathlib import Path

from aegis.audit import AuditLog
from aegis.guard import Guard
from aegis.model import Effect

PDP = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8788"
AUDIT = Path(sys.argv[2] if len(sys.argv) > 2 else ".aegis/fsp-pdp-audit.jsonl")
WORM = Path(sys.argv[3] if len(sys.argv) > 3 else ".aegis/fsp-worm-offhost.log")


def main() -> int:
    g = Guard.remote(PDP)
    print("== remote gate (signed bundle, out-of-process) ==")
    for name, tool, ti in [
        ("benign structured", "run_structured_query", {"request": {"table": "trade"}}),
        ("system in free-form", "run_query", {"query": 'select system "id" from trade where date=2015.01.08'}),
        ("protected read", "read_file", {"path": "aegis/policy.kdb.json"}),
    ]:
        d = g.check(tool, ti, principal=f"c-{name.split()[0]}")
        print(f"  {name:20} -> {d.effect.value}")

    print("\n== fail-closed when PDP unreachable ==")
    dead = Guard.remote("http://127.0.0.1:9", timeout=2.0)
    d = dead.check("run_query", {"query": "select from trade where date=2015.01.08"}, principal="x")
    print(f"  PDP down -> {d.effect.value} ({'FAIL-CLOSED ok' if d.effect is Effect.BLOCK else 'XX'})")

    print("\n== off-host WORM sink mirrored decisions ==")
    n = len(WORM.read_text().splitlines()) if WORM.exists() else 0
    print(f"  WORM sink {WORM.name}: {n} entries ({'ok' if n > 0 else 'XX empty'})")

    print("\n== audit chain verify + anchor truncation detection ==")
    a = AuditLog(AUDIT, anchor_path=str(AUDIT) + ".anchor")
    ok, cnt, err = a.verify()
    print(f"  chain verify: ok={ok} entries={cnt} {err or ''}")
    anc_ok, anc_msg = a.verify_against_anchor()
    print(f"  vs anchor (intact): {anc_ok} — {anc_msg}")
    lines = AUDIT.read_text().splitlines()
    if len(lines) >= 2:
        AUDIT.write_text("\n".join(lines[:-1]) + "\n")        # destroy the last record
        t_ok, t_msg = AuditLog(AUDIT, anchor_path=str(AUDIT) + ".anchor").verify_against_anchor()
        print(f"  vs anchor (after truncation): {t_ok} — {t_msg} "
              f"({'TRUNCATION DETECTED' if not t_ok else 'XX missed'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
