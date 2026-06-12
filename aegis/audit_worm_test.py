"""Prove the audit is tamper-PROOF, not just tamper-evident.

Demonstrates the gap and the fix:
  * plain hash-chaining does NOT catch truncation (the surviving chain still
    verifies) — so an attacker could delete recent damning entries;
  * the external anchor catches that truncation;
  * the off-host mirror still holds the full record even after the local log
    is destroyed.

Run:  python -m aegis.audit_worm_test
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from .audit import AuditLog
from .model import Action, Decision, Effect, Finding


def _mk(i: int):
    eff = Effect.BLOCK if i % 2 else Effect.ALLOW
    findings = [Finding("RULE-X", eff, f"reason {i}")] if eff is Effect.BLOCK else []
    return Action(tool="Bash", tool_input={"command": f"cmd-{i}"}), Decision(eff, findings)


def run() -> int:
    failures = 0
    print("=== Aegis tamper-PROOF audit (mirror + anchor) ===\n")

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        local = tmp / "audit.jsonl"
        mirror = tmp / "offhost" / "audit-mirror.jsonl"   # models WORM/syslog target
        anchor = tmp / "anchor.json"
        log = AuditLog(local, mirror_path=mirror, anchor_path=anchor)

        N = 8
        for i in range(N):
            log.record(*_mk(i))

        ok, n, _ = log.verify()
        c1 = ok and n == N
        failures += 0 if c1 else 1
        print(f"  {'ok ' if c1 else 'XX '} wrote {N} entries; local chain verifies ({n})")

        a_ok, a_detail = log.verify_against_anchor()
        c2 = a_ok
        failures += 0 if c2 else 1
        print(f"  {'ok ' if c2 else 'XX '} local tail matches anchor: {a_detail}")

        # Attacker truncates the local log to hide the last 3 (damning) entries.
        lines = local.read_text(encoding="utf-8").splitlines()
        local.write_text("\n".join(lines[:-3]) + "\n", encoding="utf-8")

        # Plain chain verification is FOOLED — surviving chain is internally valid.
        ok2, n2, _ = log.verify()
        c3 = ok2 and n2 == N - 3
        failures += 0 if c3 else 1
        print(f"  {'ok ' if c3 else 'XX '} after truncation, plain verify() is FOOLED "
              f"(reports clean over {n2} entries) — this is why chaining alone is not enough")

        # The anchor catches it.
        a_ok2, a_detail2 = log.verify_against_anchor()
        c4 = (not a_ok2) and "TRUNCATION" in a_detail2
        failures += 0 if c4 else 1
        print(f"  {'ok ' if c4 else 'XX '} anchor DETECTS truncation: {a_detail2}")

        # The off-host mirror still has the complete record.
        mlines = [ln for ln in mirror.read_text(encoding="utf-8").splitlines() if ln.strip()]
        c5 = len(mlines) == N
        failures += 0 if c5 else 1
        print(f"  {'ok ' if c5 else 'XX '} off-host mirror retains all {len(mlines)} entries "
              "(record survives local destruction)")

        # Even deleting the local log entirely: mirror + anchor preserve truth.
        local.unlink()
        a_ok3, a_detail3 = log.verify_against_anchor()
        c6 = not a_ok3
        failures += 0 if c6 else 1
        print(f"  {'ok ' if c6 else 'XX '} local log deleted -> anchor still flags loss: {a_detail3}")

    print(f"\n{'PASS' if failures == 0 else 'FAIL'} — {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(run())
