"""Broker SDK — one object that composes the whole enforcement stack.

`Guard` answers "may this run?". A real agent loop also needs: what happens
on REQUIRE_APPROVAL (the approvals broker), who pays for the call (the
budget ledger), and a way to wrap an existing tool registry without
rewriting the loop. `AegisSession` is that composition:

    from aegis.sdk import AegisSession
    from aegis.guard import Guard

    session = AegisSession(
        Guard.remote("http://127.0.0.1:8787"),   # or Guard.load(...)
        principal="etl-agent",
        approvals=ApprovalBroker(ApprovalStore(".aegis/approvals.json")),
        ledger=BudgetLedger(".aegis/budget.json"),
        approval_timeout=300,
    )

    gated = session.wrap_registry({"run_query": run_query, "send_email": send_email})
    ...
    result = gated["run_query"](table="trade")     # gate -> execute -> charge

Or explicitly:    result = session.run("run_query", {"table": "trade"}, run_query)

Decision handling:
  ALLOW             execute, then charge the ledger (1 action + cost_fn(...)).
  REQUIRE_APPROVAL  file a ticket and block on the broker; APPROVED =>
                    execute + charge; anything else (deny / timeout /
                    no broker configured) => BlockedAction. Fail-closed.
  BLOCK             BlockedAction. `run()` never executes a blocked call.

For loops that feed refusals back to the model instead of raising, use
`session.gate()` and `Guard.refusal_text(decision)` directly.
"""

from __future__ import annotations

from typing import Callable

from .approvals import APPROVED, ApprovalBroker
from .budget import BudgetLedger
from .guard import BlockedAction, Guard
from .model import Decision, Effect, Finding


class AegisSession:
    def __init__(
        self,
        guard: Guard,
        principal: str,
        approvals: ApprovalBroker | None = None,
        ledger: BudgetLedger | None = None,
        cost_fn: Callable[[str, dict], float] | None = None,
        approval_timeout: float = 300.0,
        cwd: str | None = None,
    ):
        self.guard = guard
        self.principal = principal
        self.approvals = approvals
        self.ledger = ledger
        self.cost_fn = cost_fn          # (tool, args) -> estimated cost units
        self.approval_timeout = approval_timeout
        self.cwd = cwd

    # -- decision only -------------------------------------------------------

    def gate(self, tool: str, args: dict) -> Decision:
        """Evaluate without executing. Resolves REQUIRE_APPROVAL through the
        broker (blocking), so the returned effect is final: ALLOW or BLOCK."""
        d = self.guard.check(tool, args or {}, principal=self.principal, cwd=self.cwd)
        if d.effect is not Effect.REQUIRE_APPROVAL:
            return d
        if self.approvals is None:
            # No human gate wired => an approval requirement is a block.
            return Decision(Effect.BLOCK, d.findings + [Finding(
                rule_id="SDK-NO-APPROVAL-BACKEND", effect=Effect.BLOCK, pack="sdk",
                reason="action requires approval but no approval broker is configured",
                remediation="Wire an ApprovalBroker into AegisSession, or change the policy effect.",
            )])
        ticket = self.approvals.request(tool, args or {}, reason=d.reason,
                                        principal=self.principal)
        status = self.approvals.wait(ticket, timeout=self.approval_timeout)
        if status == APPROVED and self.approvals.store.consume(ticket):
            return Decision(Effect.ALLOW, d.findings)
        return Decision(Effect.BLOCK, d.findings + [Finding(
            rule_id="SDK-APPROVAL-REFUSED", effect=Effect.BLOCK, pack="sdk",
            reason=f"approval ticket {ticket} resolved '{status}' — not executing",
            remediation="Have an approver grant the ticket (aegis-approve grant <id>).",
        )])

    # -- gate -> execute -> charge --------------------------------------------

    def run(self, tool: str, args: dict, executor: Callable[..., object]):
        """The full path. Raises BlockedAction instead of executing when the
        final effect is BLOCK; charges the ledger only after real execution."""
        d = self.gate(tool, args)
        if d.effect is Effect.BLOCK:
            raise BlockedAction(d)
        result = executor(**(args or {}))
        if self.ledger is not None:
            cost = self.cost_fn(tool, args or {}) if self.cost_fn else 0.0
            self.ledger.charge(self.principal, actions=1, cost=cost)
        return result

    def wrap_registry(self, registry: dict[str, Callable]) -> dict[str, Callable]:
        """Return a registry of gated callables with the same signatures."""
        def make(name: str, fn: Callable) -> Callable:
            def gated(**kwargs):
                return self.run(name, kwargs, fn)
            gated.__name__ = f"aegis_gated_{name}"
            return gated
        return {name: make(name, fn) for name, fn in registry.items()}
