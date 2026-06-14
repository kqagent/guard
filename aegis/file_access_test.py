"""Battery for the file_access pack — allowlist discipline on file-READ tools.

The FSP pilot caught a model calling read_file on positions.csv/pnl.csv; the
gate ALLOWED it because read_file was gated by a deny-list (protected_paths),
not an allowlist — only FileNotFoundError prevented a leak. This pack closes
that: a read tool may read ONLY paths under readable_paths, else block.

  1. read under an allowlisted dir -> allow
  2. read outside the allowlist (positions.csv) -> BLOCK (the pilot leak)
  3. a non-read tool is untouched by this pack
  4. read tool with no path -> fail-closed block
  5. no readable_paths configured -> fail-closed block
  6. path traversal / absolute escape -> block

Run:  python -m aegis.file_access_test
"""

from __future__ import annotations

import sys

from .engine import Engine
from .model import Action, Effect

_checks: list[tuple[str, bool]] = []


def check(name: str, ok: bool) -> None:
    _checks.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}")


def _policy(readable=("scratch/", "/data/reports/")) -> dict:
    p = {"enabled_packs": ["file_access"],
         "file_access": {"effect": "block", "read_tools": ["read_file", "Read"]}}
    if readable is not None:
        p["file_access"]["readable_paths"] = list(readable)
    return p


def _eval(policy, tool, **inp):
    return Engine(policy, audit=None).evaluate(Action(tool=tool, tool_input=inp, principal="analyst"))


def run() -> int:
    print("=== file_access — file-plane allowlist ===\n")

    d = _eval(_policy(), "read_file", path="scratch/notes.txt")
    check("read under allowlisted dir -> allow", d.effect is Effect.ALLOW)

    d = _eval(_policy(), "read_file", path="positions.csv")
    check("read of positions.csv (the pilot leak) -> BLOCK",
          d.effect is Effect.BLOCK and any(f.rule_id == "FILE-READ-NOT-ALLOWLISTED" for f in d.findings))

    d = _eval(_policy(), "read_file", path="/data/reports/eod.csv")
    check("read under second allowlisted dir -> allow", d.effect is Effect.ALLOW)

    d = _eval(_policy(), "run_query", query="select from trade")
    check("non-read tool untouched by this pack", d.effect is Effect.ALLOW)

    d = _eval(_policy(), "read_file")
    check("read tool with no path -> fail-closed block",
          d.effect is Effect.BLOCK and any(f.rule_id == "FILE-NO-PATH" for f in d.findings))

    d = _eval(_policy(readable=None), "read_file", path="scratch/x")
    check("no readable_paths configured -> fail-closed block",
          d.effect is Effect.BLOCK and any(f.rule_id == "FILE-NO-ALLOWLIST" for f in d.findings))

    d = _eval(_policy(), "read_file", path="/etc/passwd")
    check("absolute escape /etc/passwd -> block", d.effect is Effect.BLOCK)

    # the `path` and `file_path` keys are both honoured (Action.file_path)
    d = _eval(_policy(), "Read", file_path="scratch/ok.q")
    check("Read tool via file_path key, allowlisted -> allow", d.effect is Effect.ALLOW)

    failed = [n for n, ok in _checks if not ok]
    print(f"\n{'PASS' if not failed else 'FAIL'} — {len(_checks) - len(failed)}/{len(_checks)} checks")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(run())
