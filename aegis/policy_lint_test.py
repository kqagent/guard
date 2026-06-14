"""Prove the policy authoring validator (B4) catches malformed policies.

Run:  python -m aegis.policy_lint_test
"""

from __future__ import annotations

import sys

from .policy_lint import lint

GOOD = {
    "fail_mode": "closed",
    "enabled_packs": ["secrets", "kdb_guard", "resource_guard"],
    "grants": {"tools": ["run_structured_query", "read_file"]},
    "protected_paths": ["aegis/policy.kdb.json"],
    "pii_egress": {"sensitive_terms": ["pnl", "positions"]},
    "prod": {"patterns": ["(?i)\\bprod\\b"]},
    "query_proxy": {
        "allowed_tables": ["trade"],
        "require_date_tables": ["trade"],
        "max_rows": 1000000,
        "columns": {"trade": ["date", "sym", "price"]},
        "agg_fns": ["avg", "sum", "count"],
    },
}


def _checks():
    # (name, mutate_fn, expect_error_substring or None-for-warning-only)
    def m(**kw):
        import copy
        p = copy.deepcopy(GOOD)
        for k, v in kw.items():
            cur = p
            *path, last = k.split(".")
            for seg in path:
                cur = cur.setdefault(seg, {})
            cur[last] = v
        return p

    return [
        ("clean policy has no errors", GOOD, None),
        ("require_date not subset of allowed",
         m(**{"query_proxy.require_date_tables": ["trade", "ghost"]}), "not in allowed_tables"),
        ("invalid column identifier",
         {**GOOD, "query_proxy": {**GOOD["query_proxy"], "columns": {"trade": ["pri ce"]}}}, "invalid column identifier"),
        ("bad max_rows",
         {**GOOD, "query_proxy": {**GOOD["query_proxy"], "max_rows": -5}}, "max_rows must be a positive int"),
        ("unknown pack",
         {**GOOD, "enabled_packs": ["secrets", "made_up_pack"]}, "unknown pack"),
        ("invalid prod regex",
         {**GOOD, "prod": {"patterns": ["("]}}, "invalid regex"),
        ("missing enabled_packs",
         {k: v for k, v in GOOD.items() if k != "enabled_packs"}, "missing required 'enabled_packs'"),
    ]


def run() -> int:
    fails = 0
    for name, pol, expect in _checks():
        errs, warns = lint(pol)
        if expect is None:
            ok = not errs
            detail = f"errors: {errs}"
        else:
            ok = any(expect in e for e in errs)
            detail = f"expected error containing {expect!r}; got {errs}"
        print(f"  {'ok ' if ok else 'XX '} {name}")
        if not ok:
            print(f"        {detail}")
        fails += 0 if ok else 1

    # free-form run_query in grants should WARN (break-glass smell)
    errs, warns = lint({**GOOD, "grants": {"tools": ["run_query"]}})
    ok = any("run_query" in w for w in warns)
    print(f"  {'ok ' if ok else 'XX '} free-form run_query in grants warns")
    fails += 0 if ok else 1

    print(f"\n{'PASS' if fails == 0 else 'FAIL'} — {fails} failure(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(run())
