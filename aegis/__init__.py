"""Aegis — a deterministic policy gate for LLM agents.

Working name. The product thesis: guardrails an LLM cannot ignore, because
the allow/block decision is made by a separate, deterministic process at the
point of action — not injected into the model's context as advice.

Public surface:
    from aegis import Engine, Action, Effect
    engine = Engine.load("aegis/policy.json", audit_path=".aegis/audit.jsonl")
    decision = engine.evaluate(Action(tool="Bash", tool_input={"command": "rm -rf /"}))
    decision.effect  # Effect.BLOCK
"""

from .model import Action, Decision, Effect, Finding
from .engine import Engine
from .guard import Guard

__all__ = ["Action", "Decision", "Effect", "Finding", "Engine", "Guard"]
__version__ = "0.0.1"
