"""Proving battery for the broker SDK (gate -> approve -> execute -> charge).

  1. allowed call executes through a wrapped registry and charges the ledger.
  2. blocked call raises BlockedAction and the tool NEVER runs.
  3. REQUIRE_APPROVAL + granted ticket => executes; ticket is consumed.
  4. REQUIRE_APPROVAL + timeout => BlockedAction, tool never runs (fail-closed).
  5. no approval broker configured => approval requirement is a block.
  6. budget exhaustion end-to-end: charges accumulate until the cost_budget
     pack flips the same call from ALLOW to gated.

Run:  python -m aegis.sdk_test
"""

from __future__ import annotations

import sys
import tempfile
import threading
import time
from pathlib import Path

from .approvals import ApprovalBroker, ApprovalStore, main as approve_cli
from .budget import BudgetLedger
from .engine import Engine
from .guard import BlockedAction, Guard
from .sdk import AegisSession

_checks: list[tuple[str, bool]] = []


def check(name: str, ok: bool) -> None:
    _checks.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}")


def _policy(ledger: Path) -> dict:
    return {
        "enabled_packs": ["destructive_ops", "resource_guard", "cost_budget"],
        "destructive": {"effect": "block"},
        "resource_guard": {"effect": "require_approval", "big_tables": ["trade"]},
        "cost_budget": {
            "effect": "require_approval",
            "ledger": str(ledger),
            "limits": {"*": {"max_actions_per_day": 3}},
        },
    }


def run() -> int:
    print("=== broker SDK ===\n")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_sdk_"))
    ledger = BudgetLedger(tmp / "budget.json")
    store = ApprovalStore(tmp / "approvals.json")
    guard = Guard(Engine(_policy(tmp / "budget.json"), audit=None))

    calls: list[str] = []
    registry = {
        "run_cmd": lambda command: calls.append(command) or f"ran:{command}",
    }

    import os
    os.environ["AEGIS_APPROVALS"] = str(tmp / "approvals.json")

    session = AegisSession(guard, principal="etl-agent",
                           approvals=ApprovalBroker(store), ledger=ledger,
                           cost_fn=lambda tool, args: 0.25,
                           approval_timeout=8)
    gated = session.wrap_registry(registry)

    # 1. allowed call executes and charges
    out = gated["run_cmd"](command="ls scratch")
    u = ledger.usage("etl-agent")
    check("allowed call executes through wrapped registry", out == "ran:ls scratch")
    check("execution charges the ledger (1 action + cost)",
          u["actions"] == 1 and abs(u["cost"] - 0.25) < 1e-9)

    # 2. blocked call never runs
    try:
        gated["run_cmd"](command="rm -rf /data")
        check("blocked call raises BlockedAction", False)
    except BlockedAction as e:
        check("blocked call raises BlockedAction", "DST-" in e.decision.reason)
    check("blocked tool never executed", calls == ["ls scratch"])
    check("blocked call is not charged", ledger.usage("etl-agent")["actions"] == 1)

    # 3. approval granted => executes, ticket consumed
    def grant_first_pending():
        time.sleep(0.4)
        pending = [t for t in store.all() if t["status"] == "pending"]
        if pending:
            approve_cli(["grant", pending[0]["id"], "--by", "alice"])

    threading.Thread(target=grant_first_pending, daemon=True).start()
    out = gated["run_cmd"](command="q -c 'select from trade'")
    check("approval granted => call executes", out.startswith("ran:"))
    check("granted ticket recorded as consumed",
          any(t["status"] == "consumed" for t in store.all()))

    # 4. approval timeout => fail-closed, tool never runs
    fast = AegisSession(guard, principal="etl-agent",
                        approvals=ApprovalBroker(store), ledger=ledger,
                        approval_timeout=0.6)
    n_before = len(calls)
    try:
        fast.run("run_cmd", {"command": "q -c 'select from trade'"}, registry["run_cmd"])
        check("approval timeout => BlockedAction", False)
    except BlockedAction as e:
        check("approval timeout => BlockedAction",
              "SDK-APPROVAL-REFUSED" in e.decision.reason)
    check("timed-out call never executed", len(calls) == n_before)

    # 5. approval required but no broker wired => block
    bare = AegisSession(guard, principal="etl-agent", ledger=ledger)
    try:
        bare.run("run_cmd", {"command": "q -c 'select from trade'"}, registry["run_cmd"])
        check("no approval backend => block", False)
    except BlockedAction as e:
        check("no approval backend => block",
              "SDK-NO-APPROVAL-BACKEND" in e.decision.reason)

    # 6. budget exhaustion flips ALLOW to gated end-to-end
    session2 = AegisSession(guard, principal="batch-agent", ledger=ledger,
                            approvals=ApprovalBroker(store), approval_timeout=0.5)
    ran = 0
    for _ in range(3):
        try:
            session2.run("run_cmd", {"command": "ls"}, registry["run_cmd"])
            ran += 1
        except BlockedAction:
            break
    check("budget allows up to the ceiling", ran == 3)
    try:
        session2.run("run_cmd", {"command": "ls"}, registry["run_cmd"])
        check("over-budget call is gated (approval times out => blocked)", False)
    except BlockedAction as e:
        check("over-budget call is gated (approval times out => blocked)",
              "BUDGET-EXHAUSTED" in e.decision.reason)

    failed = [n for n, ok in _checks if not ok]
    print(f"\n{'PASS' if not failed else 'FAIL'} — {len(_checks) - len(failed)}/{len(_checks)} checks")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(run())
