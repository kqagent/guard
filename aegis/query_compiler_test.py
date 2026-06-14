"""Prove the structured query compiler: legitimate desk requests compile to
bounded, allowlisted q; anything off the grammar/allowlist is rejected
fail-closed; and NO request can compile to a `_DANGEROUS_Q` construct.

This is the primary query-plane control under the structured-API design — the
agent sends data, never q — so it carries the heaviest test burden.

Run:  python -m aegis.query_compiler_test
"""

from __future__ import annotations

import re
import sys

from .query_compiler import QueryCompiler, StructuredQueryRejected
from .query_proxy import _DANGEROUS_Q

CONFIG = {
    "allowed_tables": ["trade", "quote"],
    "require_date_tables": ["trade", "quote"],
    "max_rows": 1_000_000,
    "columns": {
        "trade": ["date", "time", "sym", "price", "size", "stop", "cond", "ex", "side"],
        "quote": ["date", "time", "sym", "bid", "ask", "bsize", "asize", "mode", "ex", "src"],
    },
    "agg_fns": ["avg", "sum", "min", "max", "count", "first", "last", "wavg", "dev", "var", "med"],
}
D = {"from": "2015.01.07", "to": "2015.01.08"}

# (name, request, expected)  expected = substring that must appear, or "REJECT"
CASES = [
    # ---- legitimate desk shapes compile to safe bounded q --------------------
    ("count rows", {"table": "trade", "aggs": [{"fn": "count", "as": "n"}], "date": D}, "count i"),
    ("non-finite float value (json Infinity) -> reject",
     {"table": "trade", "columns": ["price"], "date": D,
      "filters": [{"col": "price", "op": ">", "value": float("inf")}]}, "REJECT"),
    ("size-weighted vwap by sym",
     {"table": "trade", "aggs": [{"fn": "wavg", "col": "price", "weight": "size", "as": "vwap"}],
      "by": ["sym"], "date": D}, "size wavg price"),
    ("columns + sym in-list + price filter",
     {"table": "trade", "columns": ["sym", "price"], "date": D,
      "filters": [{"col": "sym", "op": "in", "value": ["AAPL", "MSFT"]},
                  {"col": "price", "op": ">", "value": 100}]}, "sym in `AAPL`MSFT"),
    ("date range -> within", {"table": "trade", "columns": ["sym"], "date": D}, "within 2015.01.07 2015.01.08"),
    ("5-minute OHLC bars (xbar timespan)",
     {"table": "trade", "aggs": [{"fn": "first", "col": "price", "as": "o"}, {"fn": "last", "col": "price", "as": "c"}],
      "bucket": {"col": "time", "size": "00:05", "as": "bar"}, "date": D}, "0D00:05 xbar time"),
    ("meta", {"table": "trade", "op": "meta"}, "meta trade"),
    ("like pattern", {"table": "trade", "columns": ["sym"], "date": D,
                      "filters": [{"col": "sym", "op": "like", "value": "AA*"}]}, 'sym like "AA*"'),
    ("numeric within", {"table": "trade", "columns": ["price"], "date": D,
                        "filters": [{"col": "price", "op": "within", "value": [10, 20]}]}, "price within (10;20)"),
    ("oversized limit is capped", {"table": "trade", "columns": ["sym"], "date": D, "limit": 999999999}, "i<1000000"),
    ("asof join trade/quote",
     {"join": {"type": "asof", "on": ["sym", "time"],
               "left": {"table": "trade", "columns": ["sym", "time", "price"], "date": D},
               "right": {"table": "quote", "columns": ["sym", "time", "bid", "ask"], "date": D}}}, "aj[`sym`time;"),
    ("distinct symbols", {"table": "trade", "columns": ["sym"], "distinct": True, "date": D}, "select distinct sym"),
    ("top-N by size (wrap-safe sublist)",
     {"table": "trade", "columns": ["sym", "size"], "date": D,
      "sort": {"col": "size", "dir": "desc"}, "limit": 5}, "5 sublist `size xdesc"),
    ("bad sort dir -> reject", {"table": "trade", "columns": ["sym"], "date": D,
                                "sort": {"col": "size", "dir": "; system"}}, "REJECT"),
    ("sort col not allowlisted -> reject", {"table": "trade", "columns": ["sym"], "date": D,
                                            "sort": {"col": "secret", "dir": "asc"}}, "REJECT"),

    # ---- off-grammar / off-allowlist / injection -> REJECT, fail-closed ------
    ("table not allowlisted", {"table": "positions", "columns": ["sym"], "date": D}, "REJECT"),
    ("column not allowlisted", {"table": "trade", "columns": ["password"], "date": D}, "REJECT"),
    ("q injection in column name", {"table": "trade", "columns": ['system "id"'], "date": D}, "REJECT"),
    ("q injection in filter value",
     {"table": "trade", "columns": ["sym"], "date": D,
      "filters": [{"col": "sym", "op": "=", "value": "AAPL`;system \"id\""}]}, "REJECT"),
    ("aggregation not allowlisted", {"table": "trade", "aggs": [{"fn": "value", "col": "price"}], "date": D}, "REJECT"),
    ("filter op not allowlisted", {"table": "trade", "columns": ["sym"], "date": D,
                                   "filters": [{"col": "sym", "op": "; system", "value": "x"}]}, "REJECT"),
    ("unsafe like pattern", {"table": "trade", "columns": ["sym"], "date": D,
                             "filters": [{"col": "sym", "op": "like", "value": '";system "id'}]}, "REJECT"),
    ("unsafe bucket size", {"table": "trade", "columns": ["sym"], "date": D,
                            "bucket": {"col": "time", "size": "00:05;x"}}, "REJECT"),
    ("missing date on partitioned table", {"table": "trade", "columns": ["sym"]}, "REJECT"),
    ("wavg without weight", {"table": "trade", "aggs": [{"fn": "wavg", "col": "price"}], "date": D}, "REJECT"),
    ("unsupported join type", {"join": {"type": "lookup", "on": ["sym"], "left": {}, "right": {}}}, "REJECT"),
    ("join key not allowlisted",
     {"join": {"type": "asof", "on": ["secret"],
               "left": {"table": "trade", "date": D}, "right": {"table": "quote", "date": D}}}, "REJECT"),

    # ---- expression-AST grammar extensions: legit shapes ---------------------
    ("computed column (ask-bid spread)",
     {"table": "quote", "select": [{"as": "spread", "expr": {"op": "sub", "args": [{"col": "ask"}, {"col": "bid"}]}}], "date": D}, "spread:(ask-bid)"),
    ("agg of computed expr (avg spread)",
     {"table": "quote", "select": [{"as": "avgspread", "expr": {"agg": "avg", "arg": {"op": "sub", "args": [{"col": "ask"}, {"col": "bid"}]}}}], "by": ["sym"], "date": D}, "avgspread:avg (ask-bid)"),
    ("ratio of aggregates (stop %)",
     {"table": "trade", "select": [{"as": "p", "expr": {"op": "div", "args": [{"agg": "sum", "arg": {"col": "stop"}}, {"agg": "count"}]}}], "date": D}, "(sum stop%count i)"),
    ("window function (cumulative sums)",
     {"table": "trade", "select": [{"as": "cum", "expr": {"win": "sums", "arg": {"col": "size"}}}], "date": D}, "cum:sums size"),
    ("window drawdown (price - maxs price)",
     {"table": "trade", "select": [{"as": "dd", "expr": {"op": "sub", "args": [{"col": "price"}, {"win": "maxs", "arg": {"col": "price"}}]}}], "date": D}, "(price-maxs price)"),
    ("countdistinct agg", {"table": "trade", "aggs": [{"fn": "countdistinct", "col": "sym", "as": "n"}], "by": ["date"], "date": D}, "count distinct sym"),
    ("sort by computed aggregate alias (top-N notional)",
     {"table": "trade", "select": [{"as": "notional", "expr": {"agg": "sum", "arg": {"op": "mul", "args": [{"col": "price"}, {"col": "size"}]}}}], "by": ["sym"], "date": D, "sort": {"col": "notional", "dir": "desc"}, "limit": 5}, "`notional xdesc"),
    ("set difference (except)",
     {"setop": "except", "left": {"table": "trade", "columns": ["sym"], "distinct": True, "date": D},
      "right": {"table": "quote", "columns": ["sym"], "distinct": True, "date": D}}, ") except ("),

    # ---- expression-AST: abuse MUST reject -----------------------------------
    ("expr operator not allowlisted", {"table": "trade", "select": [{"as": "x", "expr": {"op": "system", "args": [{"col": "price"}, {"col": "size"}]}}], "date": D}, "REJECT"),
    ("expr column not allowlisted", {"table": "trade", "select": [{"as": "x", "expr": {"col": "password"}}], "date": D}, "REJECT"),
    ("expr window fn not allowlisted", {"table": "trade", "select": [{"as": "x", "expr": {"win": "value", "arg": {"col": "price"}}}], "date": D}, "REJECT"),
    ("expr agg not allowlisted", {"table": "trade", "select": [{"as": "x", "expr": {"agg": "value", "arg": {"col": "price"}}}], "date": D}, "REJECT"),
    ("expr literal injection (string)", {"table": "trade", "select": [{"as": "x", "expr": {"op": "add", "args": [{"col": "price"}, {"lit": "1;system\"id\""}]}}], "date": D}, "REJECT"),
    ("select alias injection", {"table": "trade", "select": [{"as": "x:system\"id\"", "expr": {"col": "price"}}], "date": D}, "REJECT"),
    ("expr node with two keys (ambiguous)", {"table": "trade", "select": [{"as": "x", "expr": {"col": "price", "op": "add"}}], "date": D}, "REJECT"),
    ("setop not allowlisted", {"setop": "; system", "left": {"table": "trade", "columns": ["sym"], "date": D}, "right": {"table": "trade", "columns": ["sym"], "date": D}}, "REJECT"),
    ("sort by unknown identifier", {"table": "trade", "columns": ["sym"], "date": D, "sort": {"col": "notreal", "dir": "asc"}}, "REJECT"),
]


def run() -> int:
    qc = QueryCompiler(CONFIG)
    failures = 0
    print("=== Aegis structured query compiler ===\n")
    for name, req, expected in CASES:
        try:
            out = qc.compile(req)
            if expected == "REJECT":
                ok, detail = False, f"compiled (should have rejected): {out}"
            else:
                ok = expected in out
                detail = out
        except StructuredQueryRejected as e:
            ok = expected == "REJECT"
            detail = str(e)[:80]
        failures += 0 if ok else 1
        print(f"  {'ok ' if ok else 'XX '} {('REJECT' if expected == 'REJECT' else 'compile'):7} {name}")
        if not ok:
            print(f"          {detail}")

    # Invariant: NO positive case compiled to a dangerous construct. (The compiler
    # also enforces this internally; we re-check independently here.)
    dirty = 0
    for name, req, expected in CASES:
        if expected == "REJECT":
            continue
        try:
            low = qc.compile(req).lower()
        except StructuredQueryRejected:
            continue
        for rule, pat in _DANGEROUS_Q:
            if re.search(pat, low):
                dirty += 1
                print(f"  XX  INVARIANT VIOLATED: '{name}' compiled to a [{rule}] construct")
    failures += dirty
    print("\n  ok  no compiled output matches a _DANGEROUS_Q construct" if not dirty
          else f"\n  XX  {dirty} dangerous compiled outputs")

    print(f"\n{'PASS' if failures == 0 else 'FAIL'} — {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(run())
