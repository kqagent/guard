"""Platform-API adapter — gate any function-calling LLM loop.

Works with the Anthropic Messages API, OpenAI, Bedrock, LangChain, or any
agent framework, because they all share one shape: the model *requests* a
tool call; your code executes it. Aegis sits between request and execution.

There is no model-specific dependency here. You hand `check()` a tool name
and its arguments (however your SDK names them) and it returns a Decision.
The two helpers `from_anthropic_tool_use` / `from_openai_tool_call` just
unpack the common provider shapes for you.

Typical integration (Anthropic-style loop):

    guard = Guard.load("aegis/policy.json", audit_path=".aegis/audit.jsonl")
    ...
    for block in response.content:
        if block.type == "tool_use":
            decision = guard.check(block.name, block.input, principal=user_id)
            if decision.effect is Effect.BLOCK:
                result = guard.refusal_text(decision)   # feed back to model
            elif decision.effect is Effect.REQUIRE_APPROVAL:
                result = await ask_human(block, decision) # your approval flow
            else:
                result = run_tool(block.name, block.input)
            tool_results.append({"type": "tool_result",
                                 "tool_use_id": block.id, "content": result})

The model can only *ask*; this loop decides whether it *happens*.
"""

from __future__ import annotations

from pathlib import Path

from .engine import Engine
from .model import Action, Decision, Effect


class BlockedAction(Exception):
    """Raised by enforce() when a tool call is blocked by policy."""

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(decision.reason)


class ApprovalRequired(Exception):
    """Raised by enforce() when a tool call needs human approval."""

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(decision.reason)


class Guard:
    """A reusable, thread-safe-to-read gate around one policy bundle."""

    def __init__(self, engine: Engine):
        self.engine = engine

    @classmethod
    def load(
        cls,
        policy_path: str | Path = None,
        audit_path: str | Path | None = None,
        expected_sha256: str | None = None,
    ) -> "Guard":
        """In-process gate. Fast; suitable for low-risk dev surfaces."""
        policy_path = policy_path or Path(__file__).with_name("policy.json")
        return cls(Engine.load(policy_path, audit_path=audit_path,
                               expected_sha256=expected_sha256))

    @classmethod
    def remote(cls, endpoint: str, timeout: float = 5.0) -> "Guard":
        """Out-of-process gate against a PDP sidecar. The decision logic and
        the policy live in a process the agent cannot tamper with; if the PDP
        is unreachable, every action fails closed (BLOCK). This is the
        watertight placement for operational/prod surfaces."""
        from .pdp_client import RemotePDP
        return cls(RemotePDP(endpoint, timeout))

    # -- the core call -----------------------------------------------------

    def check(self, tool_name: str, tool_input: dict,
              principal: str | None = None, cwd: str | None = None) -> Decision:
        """Evaluate a single proposed tool call. Always returns a Decision;
        every call is recorded to the audit log."""
        return self.engine.evaluate(Action(
            tool=tool_name,
            tool_input=tool_input or {},
            principal=principal,
            cwd=cwd,
        ))

    def enforce(self, tool_name: str, tool_input: dict,
                principal: str | None = None, cwd: str | None = None) -> Decision:
        """Like check(), but raise on anything other than ALLOW. Use when you
        want a hard stop rather than to feed a refusal back to the model."""
        d = self.check(tool_name, tool_input, principal, cwd)
        if d.effect is Effect.BLOCK:
            raise BlockedAction(d)
        if d.effect is Effect.REQUIRE_APPROVAL:
            raise ApprovalRequired(d)
        return d

    @staticmethod
    def refusal_text(decision: Decision) -> str:
        """A tool_result string to feed back to the model when blocked, so it
        self-corrects instead of looping. Carries the reason + remediation,
        never the offending evidence verbatim."""
        rem = "; ".join(sorted({f.remediation for f in decision.findings if f.remediation}))
        msg = f"BLOCKED BY POLICY: {decision.reason}."
        if rem:
            msg += f" Allowed alternative: {rem}"
        return msg


# ---------------------------------------------------------------------------
# Provider shape unpackers (no SDK import required)
# ---------------------------------------------------------------------------

def from_anthropic_tool_use(block) -> tuple[str, dict]:
    """Anthropic Messages API: a content block with .type == 'tool_use',
    .name and .input (or the dict form)."""
    if isinstance(block, dict):
        return block.get("name", ""), block.get("input", {}) or {}
    return getattr(block, "name", ""), getattr(block, "input", {}) or {}


def from_openai_tool_call(tool_call) -> tuple[str, dict]:
    """OpenAI / Azure: tool_call.function.name + .arguments (JSON string)."""
    import json
    if isinstance(tool_call, dict):
        fn = tool_call.get("function", {})
        name = fn.get("name", "")
        args = fn.get("arguments", "{}")
    else:
        fn = tool_call.function
        name = fn.name
        args = fn.arguments
    if isinstance(args, str):
        try:
            args = json.loads(args or "{}")
        except json.JSONDecodeError:
            args = {"_raw_arguments": args}
    return name, args
