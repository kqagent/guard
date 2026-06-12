"""Proving battery for per-principal cost budgets.

  1. under-budget principal passes; the pack stays silent.
  2. action ceiling: ledger at the limit => BUDGET-EXHAUSTED fires.
  3. cost ceiling fires independently of the action count.
  4. principals without a limit row are not budget-gated; '*' is the default.
  5. corrupt ledger => fail-closed finding (spend cannot be verified).
  6. charge() is post-execution accounting: usage accumulates and persists.

Run:  python -m aegis.budget_test
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from .budget import BudgetLedger
from .engine import Engine
from .model import Action, Effect

_checks: list[tuple[str, bool]] = []


def check(name: str, ok: bool) -> None:
    _checks.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}")


def _policy(ledger: Path) -> dict:
    return {
        "enabled_packs": ["cost_budget"],
        "cost_budget": {
            "effect": "require_approval",
            "ledger": str(ledger),
            "limits": {
                "*": {"max_actions_per_day": 5, "max_cost_per_day": 1.0},
                "etl-agent": {"max_actions_per_day": 100},
            },
        },
    }


def _eval(policy: dict, principal: str):
    return Engine(policy, audit=None).evaluate(
        Action(tool="Bash", tool_input={"command": "ls"}, principal=principal))


def run() -> int:
    print("=== cost budgets ===\n")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_budget_"))
    ledger_path = tmp / "budget.json"
    policy = _policy(ledger_path)
    ledger = BudgetLedger(ledger_path)

    # 1. under budget => silent
    d = _eval(policy, "fresh-agent")
    check("under-budget principal is not gated", d.effect is Effect.ALLOW)

    # 6 (interleaved). charge accumulates and persists across instances
    for _ in range(5):
        ledger.charge("fresh-agent", actions=1, cost=0.1)
    u = BudgetLedger(ledger_path).usage("fresh-agent")
    check("charges accumulate and persist", u["actions"] == 5 and abs(u["cost"] - 0.5) < 1e-9)

    # 2. action ceiling
    d = _eval(policy, "fresh-agent")
    check("action ceiling => BUDGET-EXHAUSTED (require_approval)",
          d.effect is Effect.REQUIRE_APPROVAL
          and any(f.rule_id == "BUDGET-EXHAUSTED" for f in d.findings))

    # 3. cost ceiling, independent of action count
    ledger.charge("spendy-agent", actions=1, cost=2.0)
    d = _eval(policy, "spendy-agent")
    check("cost ceiling fires at 1 action", d.effect is Effect.REQUIRE_APPROVAL)

    # 4. per-principal override beats '*'; unlimited fields stay unlimited
    for _ in range(10):
        ledger.charge("etl-agent", actions=1, cost=50.0)
    d = _eval(policy, "etl-agent")
    check("explicit principal row overrides '*' (no cost ceiling set)",
          d.effect is Effect.ALLOW)
    no_limits = dict(policy, cost_budget=dict(policy["cost_budget"], limits={}))
    d = _eval(no_limits, "anyone")
    check("no limit row anywhere => pack silent", d.effect is Effect.ALLOW)

    # 5. corrupt ledger fails closed
    ledger_path.write_text("{nope", encoding="utf-8")
    d = _eval(policy, "fresh-agent")
    check("corrupt ledger => fail-closed finding",
          d.effect is Effect.REQUIRE_APPROVAL
          and any(f.rule_id == "BUDGET-LEDGER-UNAVAILABLE" for f in d.findings))

    failed = [n for n, ok in _checks if not ok]
    print(f"\n{'PASS' if not failed else 'FAIL'} — {len(_checks) - len(failed)}/{len(_checks)} checks")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(run())
