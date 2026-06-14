"""Prove a running PDP decides correctly — used by the quickstart scripts.

Connects to a PDP endpoint (default http://127.0.0.1:8787), sends a benign and
a destructive action, and asserts the verdicts. Exits non-zero if the gate
does not behave, so a clean run is a live demonstration.

    python tools/prove_gate.py [endpoint]
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.guard import Guard  # noqa: E402
from aegis.model import Effect  # noqa: E402


def main() -> int:
    endpoint = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8787"
    g = Guard.remote(endpoint)
    benign = g.check("Bash", {"command": "ls scratch"}, principal="demo")
    danger = g.check("Bash", {"command": "rm -rf /data"}, principal="demo")
    print(f"  benign  'ls scratch'   -> {benign.effect.value}")
    print(f"  danger  'rm -rf /data' -> {danger.effect.value}  [{danger.reason}]")
    if benign.effect is not Effect.ALLOW:
        print("  UNEXPECTED: benign action was not allowed", file=sys.stderr)
        return 1
    if danger.effect is not Effect.BLOCK:
        print("  UNEXPECTED: destructive action was not blocked", file=sys.stderr)
        return 1
    print("  PROVEN: the live PDP allowed benign and blocked destructive.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
