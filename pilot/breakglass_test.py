"""Prove the break-glass separation is structural (B3).

Free-form run_query is admin-only and rests on the deny-list + confinement. This
test proves the separation cannot be crossed by an analyst:
  1. On the ANALYST policy, run_query is not granted -> the gate default-denies it
     for ANY principal (it is simply not on the analyst surface).
  2. On the separate BREAK-GLASS bundle, rbac default-denies every principal except
     the named admin -> an analyst principal still cannot reach run_query there.
  3. The admin principal CAN use run_query on the break-glass bundle, and the
     action is audited (and, with the break-glass tripwire, escalated to an
     incident — exercised in the live validation, not here).

Run:  python -m pilot.breakglass_test
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from aegis.engine import Engine
from aegis.model import Action, Effect

HERE = Path(__file__).resolve().parent
ANALYST = HERE / "policy.fsp.json"
BREAKGLASS = HERE / "policy.breakglass.json"

FREE_FORM = ("run_query", {"query": "select from trade where date=2015.01.08"})


def _engine(path):
    pol = json.loads(path.read_text())
    pol.setdefault("supervisor", {})["enabled"] = False  # isolate grant/rbac logic
    return Engine(pol, mode="enforce")


def run() -> int:
    fails = 0
    analyst = _engine(ANALYST)
    bg = _engine(BREAKGLASS)

    # 1. analyst policy: run_query not granted -> blocked for an analyst principal.
    d = analyst.evaluate(Action(tool=FREE_FORM[0], tool_input=FREE_FORM[1], principal="analyst-1"))
    ok1 = d.effect is Effect.BLOCK
    print(f"  {'ok ' if ok1 else 'XX '} 1. analyst cannot reach free-form run_query on analyst policy "
          f"({d.effect.value}, {[f.rule_id for f in d.findings][:2]})")
    fails += 0 if ok1 else 1

    # 1b. and the analyst CAN use the structured tool there (sanity: not over-blocked).
    d = analyst.evaluate(Action(tool="run_structured_query", tool_input={"request": {"table": "trade"}}, principal="analyst-1"))
    ok1b = d.effect is Effect.ALLOW
    print(f"  {'ok ' if ok1b else 'XX '} 1b. analyst CAN use run_structured_query on analyst policy ({d.effect.value})")
    fails += 0 if ok1b else 1

    # 2. break-glass bundle: a non-admin (analyst) principal is rbac-denied.
    d = bg.evaluate(Action(tool=FREE_FORM[0], tool_input=FREE_FORM[1], principal="analyst-1"))
    ok2 = d.effect is Effect.BLOCK
    print(f"  {'ok ' if ok2 else 'XX '} 2. analyst principal denied on break-glass bundle "
          f"({d.effect.value}, {[f.rule_id for f in d.findings][:2]})")
    fails += 0 if ok2 else 1

    # 3. admin principal CAN use run_query on the break-glass bundle (bounded read).
    d = bg.evaluate(Action(tool=FREE_FORM[0], tool_input=FREE_FORM[1], principal="breakglass-admin"))
    ok3 = d.effect is Effect.ALLOW
    print(f"  {'ok ' if ok3 else 'XX '} 3. admin CAN use free-form run_query on break-glass bundle ({d.effect.value})")
    fails += 0 if ok3 else 1

    # 4. even the admin cannot run a dangerous free-form query (kdb_guard still applies).
    d = bg.evaluate(Action(tool="run_query", tool_input={"query": 'select system "id" from trade where date=2015.01.08'}, principal="breakglass-admin"))
    ok4 = d.effect is Effect.BLOCK
    print(f"  {'ok ' if ok4 else 'XX '} 4. admin's dangerous free-form still blocked by kdb_guard "
          f"({d.effect.value}, {[f.rule_id for f in d.findings][:2]})")
    fails += 0 if ok4 else 1

    print(f"\n{'PASS' if fails == 0 else 'FAIL'} — {fails} failure(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(run())
