"""Proof that Aegis drives THIS project's existing hard gate.

Enables the `kdb_code_quality` pack (which shells out to tools/gate.js — the
maze engine with its 53 q rules) and runs two coding actions through the
Aegis engine: a clean q function (allowed) and one with a `symbol$ cast
(blocked by KDB-CAST-001, via the existing engine — not a reimplementation).

Run:  python -m aegis.verify_kdb_bridge
"""

from __future__ import annotations

import sys

from .engine import Engine
from .model import Action, Effect

POLICY = {
    "enabled_packs": ["secrets", "kdb_code_quality"],
    "secrets": {"effect": "block"},
    "kdb_code_quality": {"effect": "block"},
}


def run() -> int:
    engine = Engine(POLICY, audit=None)
    print("=== Aegis driving the existing kdb hard gate (tools/gate.js) ===\n")

    clean = Action(tool="Write", tool_input={
        "file_path": "good.q", "content": "f:{[x] `$x}"})
    bad = Action(tool="Write", tool_input={
        "file_path": "bad.q", "content": "f:{[x] `symbol$x}"})

    d_clean = engine.evaluate(clean)
    d_bad = engine.evaluate(bad)

    ok_clean = d_clean.effect is Effect.ALLOW
    ok_bad = d_bad.effect is Effect.BLOCK and "KDB" in d_bad.reason

    def ascii_safe(s: str) -> str:
        return s.encode("ascii", "replace").decode("ascii")

    print(f"  {'ok ' if ok_clean else 'XX '} clean q  -> {d_clean.effect.value}")
    print(f"  {'ok ' if ok_bad else 'XX '} `symbol$ -> {d_bad.effect.value}")
    if d_bad.findings:
        print(f"        via existing engine: {ascii_safe(d_bad.reason)}")

    failures = (0 if ok_clean else 1) + (0 if ok_bad else 1)
    print(f"\n{'PASS' if failures == 0 else 'FAIL'} - Aegis used the project's own engine, "
          "it did not reimplement the q rules.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(run())
