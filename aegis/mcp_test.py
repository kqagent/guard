"""Prove per-MCP-server manifests (AgentBound-style zero-privilege).

A Model Context Protocol server may only use the tools its manifest declares;
an unprovisioned server has NO privileges; an undeclared tool is blocked. This
scopes capability per server, so a compromised/over-eager MCP server can't
reach beyond what the control function granted it.

Run:  python -m aegis.mcp_test
"""

from __future__ import annotations

import sys

from .engine import Engine
from .model import Action, Effect

# Detector-only policy (no default-deny grants) so the MCP manifest pack is the
# governing layer — isolates the per-server semantics.
POLICY = {
    "enabled_packs": ["mcp_manifest"],
    "mcp": {"effect": "block", "manifests": {
        "db": {"allow_tools": ["query", "schema"]},
        "search": {"allow_tools": ["*"]},   # wildcard: server trusted for all its tools
    }},
}

# (name, tool, expected_effect)
CASES = [
    ("declared tool on provisioned server", "mcp__db__query", Effect.ALLOW),
    ("second declared tool", "mcp__db__schema", Effect.ALLOW),
    ("UNDECLARED tool on provisioned server", "mcp__db__drop_table", Effect.BLOCK),
    ("wildcard server allows any tool", "mcp__search__web", Effect.ALLOW),
    ("UNPROVISIONED server (zero-privilege)", "mcp__payments__transfer", Effect.BLOCK),
    ("malformed mcp id (fail-closed)", "mcp__db", Effect.BLOCK),
    ("non-MCP tool is unaffected by this pack", "Bash", Effect.ALLOW),
]


def run() -> int:
    engine = Engine(POLICY, audit=None)
    print("=== Aegis per-MCP-server manifests (zero-privilege default) ===\n")
    failures = 0
    for name, tool, expected in CASES:
        ti = {"command": "ls"} if tool == "Bash" else {"arg": "x"}
        d = engine.evaluate(Action(tool=tool, tool_input=ti))
        ok = d.effect is expected
        failures += 0 if ok else 1
        print(f"  {'ok ' if ok else 'XX '} {d.effect.value:<7} (want {expected.value:<7}) {name}")
        if d.findings:
            print(f"          -> {d.reason}")

    print(f"\n{'PASS' if failures == 0 else 'FAIL'} — {failures} mismatch(es)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(run())
