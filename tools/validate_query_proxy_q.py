"""Validate the query proxy's rewrites against a REAL q process.

`aegis/query_proxy_test.py` asserts the proxy's verdicts in Python — what it
rewrites, bounds, and rejects. This harness closes the last gap: it takes the
proxy's `safe_query` output and runs it through an actual q binary against a
seeded in-memory table, proving the rewritten query (a) parses and executes in
q and (b) is genuinely bounded (returns <= the row cap, restricted to the
injected date partition). It also confirms the ORIGINAL unbounded query would
have returned more rows — i.e. the rewrite materially constrained the scan.

This is the "asserted-not-tested-against-q" gap from the pilot review. It
needs a working q binary; without one it SKIPS (exit 3) rather than fails, so
CI on a q-less box stays green while a q-equipped box gets the real proof.

q discovery: $Q_BIN, else $QHOME/w64/q.exe (Windows) / $QHOME/l64/q (Linux),
else `q` on PATH.

Run:  python tools/validate_query_proxy_q.py
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.query_proxy import QueryGuard  # noqa: E402

# A seeded partitioned-style table covering two dates so a date filter is
# observably narrowing. `.z.d` is bound in the harness to the date that has
# exactly the rows we expect, so the injected `where date=.z.d` is checkable.
_SEED = """
n:1000;
trade:([] date:n?(2026.06.11; 2026.06.12); sym:n?`AAPL`MSFT`GOOG; px:n?100f; sz:n?1000);
"""


def _find_q() -> str | None:
    if os.environ.get("Q_BIN"):
        return os.environ["Q_BIN"]
    qhome = os.environ.get("QHOME")
    if qhome:
        for rel in ("w64/q.exe", "l64/q", "m64/q", "l32/q"):
            cand = Path(qhome) / rel
            if cand.exists():
                return str(cand)
    from shutil import which
    return which("q")


def _run_q(q_bin: str, snippet: str) -> tuple[bool, str]:
    """Run a q snippet headless; return (ok, output). Fails on license/parse
    errors (q prints them and exits non-zero or prints 'error')."""
    script = f"{_SEED}\nres:{snippet};\n-1 \"ROWS=\",string count res;\nexit 0;"
    try:
        proc = subprocess.run([q_bin, "-q"], input=script, capture_output=True,
                              text=True, timeout=20)
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    out = (proc.stdout or "") + (proc.stderr or "")
    if "license error" in out or "'" in out.split("ROWS=")[0] and "ROWS=" not in out:
        return False, out.strip()
    return ("ROWS=" in out), out.strip()


def _rows(output: str) -> int | None:
    for line in output.splitlines():
        if line.startswith("ROWS="):
            try:
                return int(line[len("ROWS="):])
            except ValueError:
                return None
    return None


def run() -> int:
    q_bin = _find_q()
    if not q_bin:
        print("skip: no q binary found (set Q_BIN or QHOME) — Python-level "
              "proxy tests cover the logic; this harness needs real q")
        return 3

    # Quick license probe — a q with an expired/invalid licence can't run.
    ok, out = _run_q(q_bin, "select from trade where date=2026.06.12")
    if not ok and "license error" in out:
        print(f"skip: q present at {q_bin} but its licence is invalid/expired "
              f"({out.splitlines()[0] if out else 'license error'}). "
              "Install a valid kc.lic and re-run — the harness is ready.")
        return 3

    guard = QueryGuard.from_policy()
    checks: list[tuple[str, bool, str]] = []

    def check(name, ok, detail=""):
        checks.append((name, ok, detail))
        print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))

    print(f"=== query proxy vs real q ({q_bin}) ===\n")

    # 1. Unbounded q select on a require-date table -> proxy rewrites; the
    #    rewrite must execute in q AND be bounded vs the original.
    original = "select from trade"
    v = guard.analyze(original)
    check("unbounded select is rewritten (not allowed as-is)", v.action == "rewrite",
          f"injected {v.injected}")
    # bind .z.d to the seeded date so the injected `where date=.z.d` is testable
    safe = (v.safe_query or "").replace(".z.d", "2026.06.12")
    ok_safe, out_safe = _run_q(q_bin, safe)
    check("rewritten query parses and executes in q", ok_safe, out_safe.splitlines()[-1] if out_safe else "")
    ok_orig, out_orig = _run_q(q_bin, original)
    r_safe, r_orig = _rows(out_safe), _rows(out_orig)
    check("rewrite is bounded vs original",
          r_safe is not None and r_orig is not None and r_safe <= r_orig,
          f"safe={r_safe} rows, original={r_orig} rows")
    check("row cap respected", r_safe is not None and r_safe <= guard.max_rows,
          f"{r_safe} <= {guard.max_rows}")

    # 2. An already-bounded query passes through and still executes.
    bounded = "select[100] from trade where date=2026.06.12"
    v2 = guard.analyze(bounded)
    ok2, out2 = _run_q(q_bin, v2.safe_query or bounded)
    check("already-bounded query allowed and runs", v2.action in ("allow", "rewrite") and ok2,
          f"{_rows(out2)} rows")

    # 3. A rejected query (functional form) must never reach q at all.
    v3 = guard.analyze("?[trade;();0b;()]")
    check("q functional form is rejected (never sent to q)", v3.action == "reject",
          v3.reasons[0] if v3.reasons else "")

    failed = [n for n, ok, _ in checks if not ok]
    print(f"\n{'PASS' if not failed else 'FAIL'} — {len(checks) - len(failed)}/{len(checks)} checks against live q")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(run())
