"""Claude Code PreToolUse adapter.

This is the enforcement chokepoint inside Claude Code. It runs *before* the
tool executes, reads the proposed tool call from stdin, asks the engine, and
maps the decision onto Claude Code's permission protocol:

    BLOCK            -> permissionDecision "deny"   (tool does not run)
    REQUIRE_APPROVAL -> permissionDecision "ask"    (human must confirm)
    ALLOW            -> permissionDecision "allow"

The model cannot talk its way past this: the decision is made here, by a
separate process, not by the model. Whatever the model "decides" to do, this
hook decides whether it happens.

Wire it up in .claude/settings.json:

    {
      "hooks": {
        "PreToolUse": [
          {"matcher": "*",
           "hooks": [{"type": "command",
                      "command": "python -m aegis.hook"}]}
        ]
      }
    }

Fail-closed: any error here results in a deny, never a silent allow.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .engine import Engine
from .model import Action, Effect

# Resolve policy/audit relative to the package unless overridden. In a real
# deployment these point at a read-only mount the agent cannot write.
_HOME = Path(os.environ.get("AEGIS_HOME", Path(__file__).parent))
_POLICY = Path(os.environ.get("AEGIS_POLICY", _HOME / "policy.json"))
_AUDIT = Path(os.environ.get("AEGIS_AUDIT", _HOME.parent / ".aegis" / "audit.jsonl"))
_POLICY_SHA = os.environ.get("AEGIS_POLICY_SHA256")  # optional pinning


def _emit(decision_str: str, reason: str) -> None:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision_str,
            "permissionDecisionReason": reason,
        }
    }))


_EFFECT_TO_DECISION = {
    Effect.BLOCK: "deny",
    Effect.REQUIRE_APPROVAL: "ask",
    Effect.ALLOW: "allow",
}


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        _emit("deny", "Aegis: could not parse tool call (failing closed).")
        return

    action = Action(
        tool=payload.get("tool_name", ""),
        tool_input=payload.get("tool_input", {}) or {},
        cwd=payload.get("cwd"),
        principal=payload.get("session_id") or payload.get("transcript_path"),
    )

    try:
        engine = Engine.load(_POLICY, audit_path=_AUDIT, expected_sha256=_POLICY_SHA)
        decision = engine.evaluate(action)
    except Exception as e:  # nothing reaches here without a verdict
        _emit("deny", f"Aegis engine error, failing closed: {type(e).__name__}: {e}")
        return

    decision_str = _EFFECT_TO_DECISION[decision.effect]
    if decision.effect is Effect.ALLOW:
        # Stay quiet on allow so we don't bloat the agent's context.
        _emit("allow", "")
        return

    prefix = "Aegis BLOCKED this action" if decision.effect is Effect.BLOCK \
        else "Aegis requires human approval for this action"
    _emit(decision_str, f"{prefix}: {decision.reason}")


if __name__ == "__main__":
    main()
