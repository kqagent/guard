"""Prove row-level entitlements: the mandatory per-principal row filter is
NON-REMOVABLE, ANDs correctly (intersection — the agent can never widen past its
set), reaches EVERY table reference (joins, setops), is fail-closed under
default_deny, and its values use the injection-safe scalar path. Plus the
raw-select date-range cap.

This is a primary control (it decides which ROWS an agent may see), so it carries
heavy test weight.

Run:  python -m aegis.query_compiler_entitlements_test
"""

from __future__ import annotations

import sys

from .query_compiler import QueryCompiler, StructuredQueryRejected

BASE = {
    "allowed_tables": ["trade", "quote"],
    "require_date_tables": ["trade", "quote"],
    "max_rows": 1_000_000,
    "columns": {
        "trade": ["date", "sym", "price", "size", "region", "ex", "side"],
        "quote": ["date", "sym", "bid", "ask", "region", "ex", "src"],
    },
    "agg_fns": ["avg", "sum", "count", "wavg", "countdistinct"],
}
EQ_FILT = [{"col": "sym", "op": "in", "value": ["AAPL", "MSFT"]}]
ENT = {"mode": "default_deny", "principals": {
    "analyst-equities": {"row_filters": {"trade": EQ_FILT, "quote": EQ_FILT}},
    "analyst-emea": {"row_filters": {"*": [{"col": "region", "op": "in", "value": ["EMEA"]}]}},
}}
D = {"from": "2025.06.01", "to": "2025.06.01"}


def _qc(mode="default_deny", principals=None):
    ent = {"mode": mode, "principals": principals if principals is not None else ENT["principals"]}
    return QueryCompiler({**BASE, "entitlements": ent})


def run() -> int:
    fails = 0

    def check(name, cond, detail=""):
        nonlocal fails
        print(f"  {'ok ' if cond else 'XX '} {name}")
        if not cond:
            fails += 1
            if detail:
                print(f"        {detail}")

    def compiles(qc, req, principal):
        try:
            return qc.compile(req, principal=principal), None
        except StructuredQueryRejected as e:
            return None, str(e)

    qc = _qc()

    # 1. entitled principal: the mandatory predicate is ANDed into the WHERE.
    out, _ = compiles(qc, {"table": "trade", "columns": ["sym", "price"], "date": D}, "analyst-equities")
    check("1 entitled query carries mandatory `sym in (AAPL;MSFT)`", out and "sym in `AAPL`MSFT" in out, out)

    # 2. CANNOT ESCAPE: asking for a non-entitled symbol ANDs -> intersection.
    out, _ = compiles(qc, {"table": "trade", "columns": ["sym"], "date": D,
                           "filters": [{"col": "sym", "op": "in", "value": ["GOOG"]}]}, "analyst-equities")
    check("2 agent's GOOG filter does NOT replace the entitlement (both ANDed)",
          out and "sym in `GOOG" in out and "sym in `AAPL`MSFT" in out, out)

    # 3. JOIN: both sides carry their table's entitlement predicate.
    join_req = {"join": {"type": "left", "on": ["sym"],
                         "left": {"table": "trade", "by": ["sym"], "aggs": [{"fn": "count", "as": "n"}], "date": D},
                         "right": {"table": "quote", "by": ["sym"], "aggs": [{"fn": "count", "as": "m"}], "date": D}}}
    out, _ = compiles(qc, join_req, "analyst-equities")
    check("3 join: BOTH sides carry the entitlement", out and out.count("sym in `AAPL`MSFT") == 2, out)

    # 4. SETOP: both sides carry the entitlement.
    setop_req = {"setop": "except",
                 "left": {"table": "trade", "columns": ["sym"], "distinct": True, "date": D},
                 "right": {"table": "quote", "columns": ["sym"], "distinct": True, "date": D}}
    out, _ = compiles(qc, setop_req, "analyst-equities")
    check("4 setop: BOTH sides carry the entitlement", out and out.count("sym in `AAPL`MSFT") == 2, out)

    # 5. un-entitled principal under default_deny -> reject (sees nothing).
    out, err = compiles(qc, {"table": "trade", "columns": ["sym"], "date": D}, "analyst-nobody")
    check("5 un-entitled principal under default_deny -> REJECT", out is None and "denied" in (err or ""), err)

    # 6. principal entitled on a DIFFERENT table only -> reject for the queried one.
    out, err = compiles(_qc(principals={"x": {"row_filters": {"quote": EQ_FILT}}}),
                        {"table": "trade", "columns": ["sym"], "date": D}, "x")
    check("6 entitled on quote but querying trade -> REJECT (default_deny, no `*`)", out is None, err)

    # 7. wildcard `*` entitlement applies to any table.
    out, _ = compiles(qc, {"table": "trade", "columns": ["sym"], "date": D}, "analyst-emea")
    check("7 wildcard `*` entitlement applies (region in (`EMEA))", out and "region in `EMEA" in out, out)

    # 8. injection-safe: a hostile entitlement VALUE cannot inject.
    out, err = compiles(_qc(mode="open", principals={"x": {"row_filters": {"trade": [{"col": "sym", "op": "in", "value": ["AAPL`;system\"id\""]}]}}}),
                        {"table": "trade", "columns": ["sym"], "date": D}, "x")
    check("8 hostile entitlement value -> REJECT (scalar path)", out is None and "unsafe" in (err or ""), err)

    # 9. injection-safe: a hostile entitlement COLUMN cannot inject (allowlist).
    out, err = compiles(_qc(mode="open", principals={"x": {"row_filters": {"trade": [{"col": "sym; delete", "op": "=", "value": 1}]}}}),
                        {"table": "trade", "columns": ["sym"], "date": D}, "x")
    check("9 hostile entitlement column -> REJECT (allowlist)", out is None, err)

    # 10. open mode (default off): no entitlement config -> no row filter (back-compat).
    out, _ = compiles(QueryCompiler(BASE), {"table": "trade", "columns": ["sym"], "date": D}, "anyone")
    check("10 no entitlements configured -> no row filter injected", out and "sym in" not in out, out)

    # 11. principal is NOT taken from the request body (agent can't set it).
    #     A 'principal' key in the request is ignored; only the compile() arg counts.
    out, err = compiles(qc, {"table": "trade", "columns": ["sym"], "date": D, "principal": "analyst-equities"}, None)
    check("11 principal in request body is ignored (None arg -> default_deny reject)", out is None, err or out)

    # --- raw-select date-range cap ------------------------------------------
    qspan = QueryCompiler({**BASE, "max_partition_span": 5})
    out, err = compiles(qspan, {"table": "trade", "columns": ["sym"], "date": {"from": "2025.06.01", "to": "2025.06.20"}}, None)
    check("12 raw select over 20-day range > span cap 5 -> REJECT", out is None and "spans" in (err or ""), err)
    out, _ = compiles(qspan, {"table": "trade", "columns": ["sym"], "date": {"from": "2025.06.01", "to": "2025.06.03"}}, None)
    check("13 raw select within span cap -> OK", out is not None, err)
    out, _ = compiles(qspan, {"table": "trade", "aggs": [{"fn": "count", "as": "n"}], "date": {"from": "2025.06.01", "to": "2025.06.30"}}, None)
    check("14 REDUCING query over wide range -> OK (exempt from span cap)", out is not None, "reducing must not be span-capped")

    # --- review fixes: combine `*`+table, and gate `meta` -------------------
    # 15. `*` baseline AND table-specific must BOTH apply (no widening by table
    #     rule replacing the global one). A principal with both is the narrowest.
    both = _qc(principals={"p": {"row_filters": {
        "*": [{"col": "region", "op": "in", "value": ["EMEA"]}],
        "trade": [{"col": "sym", "op": "in", "value": ["AAPL", "MSFT"]}]}}})
    out, _ = compiles(both, {"table": "trade", "columns": ["sym", "price"], "date": D}, "p")
    check("15 `*` AND table-specific BOTH applied (region AND sym), not replaced",
          out and "region in `EMEA" in out and "sym in `AAPL`MSFT" in out, out)
    # the `*`-only table still gets the baseline (sanity: no table rule to add)
    out, _ = compiles(both, {"table": "quote", "columns": ["sym"], "date": D}, "p")
    check("15b `*` baseline still applies to a table with no specific rule",
          out and "region in `EMEA" in out and "sym in" not in out, out)

    # 16. meta returns no rows but must still honour default-deny: an
    #     un-entitled principal cannot enumerate a table's schema.
    out, err = compiles(qc, {"table": "trade", "op": "meta"}, "analyst-nobody")
    check("16 meta by un-entitled principal under default_deny -> REJECT",
          out is None and "denied" in (err or ""), err or out)
    out, _ = compiles(qc, {"table": "trade", "op": "meta"}, "analyst-equities")
    check("16b meta by an entitled principal -> OK", out == "meta trade", out)

    print(f"\n{'PASS' if fails == 0 else 'FAIL'} — {fails} failure(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(run())
