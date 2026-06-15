"""Prove the policy-correctness linter catches each schema-drift class — both the
TOO-TIGHT (availability) and TOO-LOOSE (safety) directions.

Pure / stdlib-only: the diff logic is policy-vs-schema dicts, so this runs in CI
with no kdb+. The live-HDB schema loader (aegis.policy_schema_diff.schema_from_hdb)
is exercised separately by the conformance tier.

Run:  python -m aegis.policy_schema_diff_test
"""

from __future__ import annotations

import copy
import sys

from .policy_schema_diff import ERROR, diff, normalise_schema

# A consistent baseline: policy matches schema exactly.
POLICY = {
    "query_proxy": {
        "allowed_tables": ["trade", "quote"],
        "require_date_tables": ["trade", "quote"],
        "columns": {
            "trade": ["date", "sym", "region", "price"],
            "quote": ["date", "sym", "region", "bid"],
        },
    },
    "entitlements": {"mode": "default_deny", "principals": {
        "emea": {"row_filters": {"*": [{"col": "region", "op": "in", "value": ["EMEA"]}]}},
        "eq": {"row_filters": {"trade": [{"col": "sym", "op": "in", "value": ["AAPL"]}]}},
    }},
}
SCHEMA = {
    "trade": {"columns": ["date", "sym", "region", "price"], "partitioned": True},
    "quote": {"columns": ["date", "sym", "region", "bid"], "partitioned": True},
}


def run() -> int:
    fails = 0

    def check(name, cond, detail=""):
        nonlocal fails
        print(f"  {'ok ' if cond else 'XX '} {name}")
        if not cond:
            fails += 1
            if detail:
                print(f"        {detail}")

    def codes(policy, schema):
        return [f.code for f in diff(policy, normalise_schema(schema))]

    def errs(policy, schema):
        return [f.code for f in diff(policy, normalise_schema(schema)) if f.level == ERROR]

    # 0. baseline is clean (no findings at all).
    base = diff(POLICY, normalise_schema(SCHEMA))
    check("0 consistent policy+schema -> no findings", not base, [repr(x) for x in base])

    # Each scenario mutates a deep copy and asserts the specific code fires.
    def scenario(name, expect_code, mut_policy=None, mut_schema=None):
        p, s = copy.deepcopy(POLICY), copy.deepcopy(SCHEMA)
        if mut_policy:
            mut_policy(p)
        if mut_schema:
            mut_schema(s)
        got = codes(p, s)
        check(f"{name} -> {expect_code}", expect_code in got, f"got {got}")

    # 1. TOO TIGHT / availability ------------------------------------------
    scenario("1 table dropped from the estate", "TABLE-MISSING",
             mut_schema=lambda s: s.pop("quote"))
    scenario("2 allowlisted column no longer exists", "COL-MISSING",
             mut_schema=lambda s: s["trade"]["columns"].remove("price"))
    scenario("3 entitlement col not in the allowlist (locks principal out)", "ENT-COL-NOTALLOWED",
             mut_policy=lambda p: p["query_proxy"]["columns"]["trade"].remove("region"))
    scenario("4 entitlement col dropped from the table", "ENT-COL-MISSING",
             mut_schema=lambda s: s["trade"]["columns"].remove("sym"))
    scenario("5 entitlement references an un-allowed table", "ENT-TABLE-UNKNOWN",
             mut_policy=lambda p: p["entitlements"]["principals"]["eq"]["row_filters"]
             .__setitem__("ghosttbl", [{"col": "sym", "op": "=", "value": "X"}]))
    scenario("6 principal with no rules under default-deny", "PRINCIPAL-NORULES",
             mut_policy=lambda p: p["entitlements"]["principals"].__setitem__("ghost", {"row_filters": {}}))

    # 2. TOO LOOSE / safety -------------------------------------------------
    scenario("7 partitioned table missing its required date bound", "PART-NO-DATE",
             mut_policy=lambda p: p["query_proxy"]["require_date_tables"].remove("trade"))
    scenario("8 new column appeared, not yet triaged into the allowlist", "NEW-COL",
             mut_schema=lambda s: s["trade"]["columns"].append("mnpi"))
    scenario("9 require_date expects partitioning the table doesn't have", "DATE-NOT-PART",
             mut_schema=lambda s: s["trade"].__setitem__("partitioned", False))

    # 3. internal consistency (no schema needed) ---------------------------
    scenario("10 columns map names a table not in allowed_tables", "COLS-TABLE-UNKNOWN",
             mut_policy=lambda p: p["query_proxy"]["columns"].__setitem__("orphan", ["x"]))
    scenario("11 require_date names a table not in allowed_tables", "REQDATE-TABLE-UNKNOWN",
             mut_policy=lambda p: p["query_proxy"]["require_date_tables"].append("orphan"))

    # 4. errors really gate; warnings do not -------------------------------
    only_warn = errs(POLICY, {**copy.deepcopy(SCHEMA),
                              "trade": {"columns": ["date", "sym", "region", "price", "extra"], "partitioned": True}})
    check("12 a NEW-COL-only drift produces a WARN, not an ERROR", not only_warn, only_warn)

    print(f"\n{'PASS' if fails == 0 else 'FAIL'} — {fails} failure(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(run())
