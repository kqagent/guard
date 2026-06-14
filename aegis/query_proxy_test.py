"""Prove the query proxy: unsafe queries are rewritten to safe ones or
rejected; the database only ever sees bounded, allowlisted, read-only queries.

Run:  python -m aegis.query_proxy_test
"""

from __future__ import annotations

import sys
from pathlib import Path

from .query_proxy import QueryGuard

# (name, query, expected_action, must_appear_in_safe_query_or_None)
CASES = [
    ("q: unbounded scan of partitioned table",
     "select from trade", "rewrite", "where date=.z.d"),
    ("q: unbounded scan gets a partition-safe row cap too",
     "select from trade", "rewrite", "i<1000000"),
    ("q: has date, still gets a row cap",
     "select sym,price from quote where date=2024.01.01", "rewrite", "i<1000000"),
    ("q: already bounded (select[N]) -> allow",
     "select[100] from quote where date=.z.d", "allow", None),
    ("q: list literal with internal ; is NOT multi-statement",
     "select[100] from quote where date=.z.d, sym in (`AAPL;`MSFT)", "allow", None),
    ("q: non-partitioned ref table, capped",
     "select from ref", "rewrite", "i<1000000"),
    ("q: commented-out where must NOT fool the bounded check",
     "select from trade / where date=.z.d", "rewrite", "where date=.z.d"),
    ("q: table not on allowlist -> reject",
     "select from secret_book", "reject", None),
    ("q: mutation -> reject",
     "delete from trade", "reject", None),
    ("q: functional form -> reject (fail closed)",
     "?[trade;();0b;()]", "reject", None),
    ("q: multiple statements -> reject",
     "select from quote where date=.z.d; select from trade", "reject", None),
    ("sql: unbounded partitioned -> reject (no date predicate)",
     "SELECT * FROM trades", "reject", None),
    ("sql: ref table, LIMIT injected",
     "SELECT * FROM ref", "rewrite", "LIMIT 1000000"),
    ("sql: bounded -> allow",
     "SELECT * FROM ref LIMIT 50", "allow", None),
]


def run() -> int:
    guard = QueryGuard.from_policy(Path(__file__).with_name("policy.json"))
    print("=== Aegis query proxy — ground-truth enforcement ===\n")
    failures = 0
    for name, query, expected, must_contain in CASES:
        v = guard.analyze(query)
        ok = v.action == expected
        if ok and must_contain is not None:
            ok = v.safe_query is not None and must_contain in v.safe_query
        failures += 0 if ok else 1
        mark = "ok " if ok else "XX "
        print(f"  {mark} {expected:<7} {name}")
        if v.action == "rewrite":
            print(f"          in : {query}")
            print(f"          out: {v.safe_query}")
            print(f"          why: {'; '.join(v.reasons)}")
        elif v.action == "reject":
            print(f"          rejected: {'; '.join(v.reasons)}")

    # enforce() raises on reject — prove the DB never receives a rejected query.
    from .query_proxy import QueryRejected
    raised = False
    try:
        guard.enforce("select from secret_book")
    except QueryRejected:
        raised = True
    failures += 0 if raised else 1
    print(f"\n  {'ok ' if raised else 'XX '} enforce() raises QueryRejected on a disallowed query")

    print(f"\n{'PASS' if failures == 0 else 'FAIL'} — {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(run())
