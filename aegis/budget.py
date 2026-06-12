"""Per-principal cost budgets — the resource_guard's accounting twin.

resource_guard vetoes single runaway actions; this ledger bounds the
AGGREGATE: how many actions and how much estimated spend a principal may
accumulate per UTC day. An agent that is individually polite on every call
can still burn a model budget or hammer a system 10k times — that is what
a budget catches.

Split of responsibilities (keeps detectors pure):
  * `detect_cost_budget` (in detectors.py) READS the ledger and vetoes when
    a principal is at/over its limit. Same input, same output — the ledger
    file is part of the input.
  * Charging is done by the EXECUTION layer (sdk.AegisSession charges after
    a tool call actually runs) — never by the detector, so evaluating an
    action twice cannot double-spend.

Fail-closed: an unreadable/corrupt ledger makes the detector fire (the
budget cannot be verified, so the spend is not authorized), and the ledger
itself refuses to charge into a corrupt file.

policy.json:
    "cost_budget": {
        "effect": "require_approval",        # or "block"
        "ledger": ".aegis/budget.json",
        "limits": {
            "*":         {"max_actions_per_day": 500, "max_cost_per_day": 25.0},
            "etl-agent": {"max_actions_per_day": 2000}
        }
    }
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class LedgerError(Exception):
    """The ledger cannot be read or written safely."""


class BudgetLedger:
    """One JSON file: {principal: {date: {"actions": n, "cost": x}}}.

    Same O_EXCL lock-file discipline as the approval store — adequate for
    agent-action rates, portable across Windows/POSIX.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = self.path.with_suffix(self.path.suffix + ".lock")

    def _acquire(self, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fd = os.open(self._lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(fd)
                return
            except FileExistsError:
                if time.monotonic() > deadline:
                    raise LedgerError(f"ledger lock held: {self._lock}")
                time.sleep(0.05)

    def _release(self) -> None:
        try:
            os.unlink(self._lock)
        except OSError:
            pass

    def _read(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8") or "{}")
        except json.JSONDecodeError as e:
            raise LedgerError(f"ledger corrupt: {e}") from e

    def usage(self, principal: str, day: str | None = None) -> dict:
        """{"actions": n, "cost": x} for the principal on `day` (default today)."""
        day = day or _today()
        u = self._read().get(principal, {}).get(day, {})
        return {"actions": int(u.get("actions", 0)), "cost": float(u.get("cost", 0.0))}

    def charge(self, principal: str, actions: int = 1, cost: float = 0.0) -> dict:
        """Record spend AFTER execution. Returns the new usage for today."""
        self._acquire()
        try:
            data = self._read()
            day = _today()
            u = data.setdefault(principal, {}).setdefault(day, {"actions": 0, "cost": 0.0})
            u["actions"] = int(u.get("actions", 0)) + actions
            u["cost"] = float(u.get("cost", 0.0)) + cost
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
            os.replace(tmp, self.path)
            return dict(u)
        finally:
            self._release()


def limits_for(principal: str, cfg: dict) -> dict | None:
    """Resolve the limit row: exact principal, else '*', else None (no budget)."""
    limits = cfg.get("limits", {})
    return limits.get(principal) or limits.get("*")


def over_budget(principal: str, cfg: dict) -> tuple[bool, str]:
    """Pure read used by the detector. Returns (over, why).

    Raises LedgerError when the ledger cannot be trusted — the caller
    (detector) converts that into a fail-closed finding.
    """
    row = limits_for(principal, cfg)
    if row is None:
        return False, ""
    ledger_path = cfg.get("ledger")
    if not ledger_path:
        raise LedgerError("cost_budget enabled but no 'ledger' path configured")
    u = BudgetLedger(ledger_path).usage(principal)
    max_a = row.get("max_actions_per_day")
    if max_a is not None and u["actions"] >= max_a:
        return True, f"{u['actions']}/{max_a} actions today"
    max_c = row.get("max_cost_per_day")
    if max_c is not None and u["cost"] >= max_c:
        return True, f"{u['cost']:.2f}/{max_c:.2f} cost today"
    return False, ""
