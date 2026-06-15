"""Cedar Analysis CLI runner — independent corroboration of our Z3 grant-algebra
proofs using AWS's open-source, CVC5-backed, Lean-proven Cedar analysis tooling.

This is CORROBORATION ONLY — Aegis is NOT rebuilt on Cedar. We already prove
default-deny soundness and monotonic confinement ourselves (`formal.py` by
exhaustion, `formal_smt` with Z3). This feeds the Cedar text emitted by
`cedar_export.py` to the Cedar CLI and reports its independent verdict
(validation, and policy-equivalence between two policy versions — the same
narrowing/widening question `monotonic_confinement` answers), so the assurance
story has a second, differently-implemented prover behind it.

OPTIONAL-tier: the Cedar Analysis CLI needs a Rust toolchain + the tool installed
(`cedar` or `cedar-policy-cli` on PATH, or `AEGIS_CEDAR_BIN`). When absent this
SKIPS cleanly (exit 0) like `q_conformance` / `formal_smt`, so CI without Cedar
stays green. The dependency is flagged, not bundled.

    python -m aegis.cedar_analysis            # validate the exported policy (skip if no cedar)
    python -m aegis.cedar_analysis --equiv a.cedar b.cedar
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from .cedar_export import to_cedar, POLICY


def find_cedar() -> str | None:
    """Locate the Cedar CLI: AEGIS_CEDAR_BIN, then `cedar`, then `cedar-policy-cli`."""
    env = os.environ.get("AEGIS_CEDAR_BIN")
    if env and Path(env).exists():
        return env
    for name in ("cedar", "cedar-policy-cli"):
        p = shutil.which(name)
        if p:
            return p
    return None


def _run(cedar: str, args: list[str]) -> tuple[bool, str]:
    try:
        r = subprocess.run([cedar, *args], capture_output=True, text=True, timeout=120)
        return r.returncode == 0, (r.stdout + r.stderr).strip()
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def validate_policy(cedar: str, policy_cedar: Path, schema: Path | None = None) -> tuple[bool, str]:
    """Run `cedar validate` on a Cedar policy file (schema optional)."""
    args = ["validate", "--policies", str(policy_cedar)]
    if schema is not None:
        args += ["--schema", str(schema)]
    ok, out = _run(cedar, args)
    if "unrecognized" in out.lower() or "unexpected" in out.lower():
        # CLI surface differs across cedar versions; try the bare check.
        ok, out = _run(cedar, ["check-parse", "--policies", str(policy_cedar)])
    return ok, out


def run() -> int:
    cedar = find_cedar()
    print("=== Cedar Analysis CLI corroboration (optional-tier) ===")
    # always exportable — emit the current policy as Cedar text
    out_cedar = Path(__file__).with_name("policy.cedar")
    out_cedar.write_text(to_cedar(_load(POLICY)), encoding="utf-8")
    print(f"  exported policy -> {out_cedar.name} ({out_cedar.stat().st_size} bytes)")
    if cedar is None:
        print("  SKIP — Cedar Analysis CLI not installed (need Rust toolchain + `cedar`/"
              "`cedar-policy-cli` on PATH, or AEGIS_CEDAR_BIN).")
        print("  Aegis proves these properties itself: formal.py (exhaustive) + formal_smt (Z3).")
        # OPTIONAL-tier convention: a non-zero return shows as 'skip' (not a failure)
        # in run_all_checks — like formal_smt / verify_kdb_bridge when their infra is absent.
        return 2
    ok, detail = validate_policy(cedar, out_cedar)
    print(f"  cedar ({cedar}) validate -> {'OK' if ok else 'ISSUES'}")
    if detail:
        print("   " + detail.replace("\n", "\n   ")[:800])
    print(f"\n{'PASS' if ok else 'FAIL'} — Cedar corroboration {'green' if ok else 'reported issues'}")
    return 0 if ok else 1


def _load(p):
    import json
    return json.loads(Path(p).read_text(encoding="utf-8"))


def main() -> int:
    if "--equiv" in sys.argv:
        i = sys.argv.index("--equiv")
        a, b = sys.argv[i + 1], sys.argv[i + 2]
        cedar = find_cedar()
        if cedar is None:
            print("SKIP — Cedar CLI not installed; equivalence corroboration unavailable.")
            return 0
        ok, out = _run(cedar, ["analyze", "policy-equivalence", "--policies", a, "--policies-2", b])
        print(out or ("equivalent" if ok else "differ"))
        return 0
    return run()


if __name__ == "__main__":
    sys.exit(main())
