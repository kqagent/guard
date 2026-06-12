"""Core data model: the action being judged, and the decision returned.

Deliberately dependency-free (stdlib only). The enforcement path must never
fail because a third-party package is missing — that would be a fail-open.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Effect(str, Enum):
    """The three outcomes. Ordered by severity for 'most severe wins'."""

    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


_SEVERITY_ORDER = {Effect.ALLOW: 0, Effect.REQUIRE_APPROVAL: 1, Effect.BLOCK: 2}


def most_severe(effects: list[Effect]) -> Effect:
    """Combine findings: any block wins, else any approval, else allow."""
    if not effects:
        return Effect.ALLOW
    return max(effects, key=lambda e: _SEVERITY_ORDER[e])


# Tool names that mutate the workspace (coding surface) vs. everything else
# (operational surface). The engine treats both identically; the split only
# drives which packs are worth running and how findings are labelled.
_CODING_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}


@dataclass
class Action:
    """A single agent action, normalised from a tool call.

    This is the universal unit of agent behaviour. In Claude Code it comes
    from the PreToolUse hook (tool_name + tool_input). Behind a gateway it
    comes from the model's tool-call before dispatch. Same shape either way.
    """

    tool: str
    tool_input: dict
    cwd: str | None = None
    principal: str | None = None  # who/what is acting (agent id, user, service)

    @property
    def command(self) -> str | None:
        """Shell command, for Bash-like tools."""
        if self.tool in ("Bash", "Shell", "PowerShell"):
            return self.tool_input.get("command")
        return None

    @property
    def file_path(self) -> str | None:
        return self.tool_input.get("file_path") or self.tool_input.get("path")

    @property
    def content(self) -> str | None:
        """Proposed file content. Write uses 'content'; Edit uses 'new_string'."""
        return self.tool_input.get("content") or self.tool_input.get("new_string")

    @property
    def surface(self) -> str:
        return "coding" if self.tool in _CODING_TOOLS else "operational"

    def searchable_text(self) -> str:
        """Everything a detector might want to scan: command, content, args."""
        parts: list[str] = []
        if self.command:
            parts.append(self.command)
        if self.content:
            parts.append(self.content)
        # Catch anything else string-valued (e.g. MCP tool args, urls).
        for k, v in self.tool_input.items():
            if isinstance(v, str) and v not in parts:
                parts.append(v)
        return "\n".join(parts)


@dataclass
class Finding:
    """One rule firing. Multiple findings can attach to one decision."""

    rule_id: str
    effect: Effect
    reason: str
    pack: str = ""
    remediation: str = ""
    evidence: str = ""  # short, already-redacted snippet of what matched


@dataclass
class Decision:
    effect: Effect                       # the ENFORCED effect (ALLOW in monitor mode)
    findings: list[Finding] = field(default_factory=list)
    shadow_effect: Effect | None = None  # in monitor mode, the would-be effect

    @property
    def blocked(self) -> bool:
        return self.effect is Effect.BLOCK

    @property
    def reason(self) -> str:
        if not self.findings:
            return "no policy rule fired"
        # Lead with the most severe findings.
        ranked = sorted(
            self.findings,
            key=lambda f: _SEVERITY_ORDER[f.effect],
            reverse=True,
        )
        lines = [f"[{f.rule_id}] {f.reason}" for f in ranked]
        return "; ".join(lines)

    def to_dict(self) -> dict:
        return {
            "effect": self.effect.value,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "effect": f.effect.value,
                    "pack": f.pack,
                    "reason": f.reason,
                    "remediation": f.remediation,
                    "evidence": f.evidence,
                }
                for f in self.findings
            ],
        }
