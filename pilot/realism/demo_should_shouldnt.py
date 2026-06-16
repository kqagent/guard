#!/usr/bin/env python3
"""Live, EXPLAINED "should / shouldn't work" demonstration of the Aegis gate against
the REAL ~4-billion-row kdb+ estate (~/aegis-hdb/fsp1, 50 partitions x 10M rows).

Everything is executed, not described, and each step shows what the gate is doing
under the hood:
  * the agent never sends q code — it sends a STRUCTURED REQUEST;
  * the COMPILER (loaded from a real policy) is the control: it validates every
    field against the real schema's allowlist, injects mandatory bounds + the
    principal's row entitlement, and emits the ONLY q that ever runs — or refuses;
  * compiled queries run on a live HDB (reusing realism_soak's start_hdb/q_eval),
    so every row count and timing is real;
  * the IFC section uses aegis.ifc directly.

Run:  .venv/bin/python pilot/realism/demo_should_shouldnt.py
Writes pilot/realism/DEMO_should_shouldnt.md and prints the same transcript.
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO))

from aegis.query_compiler import QueryCompiler, StructuredQueryRejected
from aegis import ifc
from pilot.realism.realism_soak import (Q_BIN, q_eval, q_match, start_hdb,
                                        available_dates)

POLICY = HERE / "policy.realism.demo.json"
OUT_MD = HERE / "DEMO_should_shouldnt.md"
HDB = str(Path.home() / "aegis-hdb" / "fsp1" / "hdb")
PORT = 31999
PRINCIPAL = "analyst-equities"
ENT_PRED = "sym in `AAPL`MSFT"          # this principal's mandatory row filter

_buf: list[str] = []


def emit(line: str = "") -> None:
    _buf.append(line)
    print(line)


def rule() -> None:
    emit("\n" + "-" * 78 + "\n")


def run_timed(port: int, q: str) -> tuple[int, int]:
    """Execute compiled q on the live HDB; return (row_count, elapsed_ms), timed
    server-side so the number is the query time, not q-process startup."""
    thunk = f"{{[] st:.z.p; res:({q}); (count res;`long$(.z.p-st)%1000000)}}[]"
    out = q_eval(port, thunk, timeout=300)
    nums = re.findall(r"-?\d+", out)
    if out.startswith("ERR") or len(nums) < 2:
        return -1, -1
    return int(nums[0]), int(nums[1])


def q_scalar(port: int, expr: str) -> str:
    return q_eval(port, expr, timeout=300).strip()


def gate_transforms(compiled: str) -> list[tuple[str, str, str]]:
    """Detect, from the compiled q, the safety transforms the gate injected — so
    the demo can show what was added 'under the hood'. Returns (label, snippet, why)."""
    notes = []
    m = re.search(r"date within \S+ \S+|date=\d{4}\.\d{2}\.\d{2}", compiled)
    if m:
        notes.append(("partition bound", m.group(0),
                       "required — restricts the scan to named date partitions, never the whole DB"))
    if ENT_PRED in compiled:
        notes.append(("entitlement filter", ENT_PRED,
                      f"the MANDATORY row filter for '{PRINCIPAL}', injected by the gate from the "
                      "policy — the agent cannot set, remove, or widen it"))
    m = re.search(r"i<(\d+)", compiled)
    if m:
        notes.append(("materialisation cap", f"i<{m.group(1)}",
                      "bounds rows read off disk per partition (RAW listings only — never added to "
                      "aggregations, where it would corrupt the result)"))
    m = re.search(r"(\d+) sublist", compiled)
    if m:
        notes.append(("result cap", f"{m.group(1)} sublist",
                      "bounds the rows returned to the agent (applied to the final result)"))
    return notes


def show_request(req: dict) -> None:
    emit("WHAT THE ANALYST ASKED  (a structured request — note: no q code anywhere):")
    emit(f"    {req}")


def show_compiled(compiled: str) -> None:
    emit("WHAT THE GATE EMITTED   (the ONLY q that will run):")
    emit(f"    {compiled}")
    notes = gate_transforms(compiled)
    if notes:
        emit("WHAT THE GATE ADDED UNDER THE HOOD:")
        for label, snip, why in notes:
            emit(f"    - {label:<18} {snip}")
            emit(f"      {' ':<18} ^ {why}")


# ---------------------------------------------------------------------------
DATES = available_dates(HDB)
D0 = DATES[0]                       # 2025.06.01


def section1(qc: QueryCompiler, port: int) -> dict:
    emit("## 1. SHOULD WORK — real queries, compiled and executed on the live HDB\n")
    emit("The point of this section: legitimate analyst questions are answered with REAL")
    emit("data, but every query the gate emits is bounded and scoped to what this analyst")
    emit(f"is allowed to see. Principal `{PRINCIPAL}` is entitled to `{ENT_PRED}` only.")
    emit(f"HDB: `{HDB}` — {len(DATES)} partitions x 10M rows (500M on this node; 4B across the estate).\n")
    passed = 0

    cases = [
        ("a. Filtered raw select (size>500), one partition",
         {"table": "trade", "columns": ["sym", "time", "price", "size"],
          "filters": [{"col": "size", "op": ">", "value": 500}],
          "date": {"from": D0, "to": D0}},
         "raw-sample"),
        ("b. Aggregation — avg price + total size, grouped by sym, one partition",
         {"table": "trade",
          "aggs": [{"fn": "avg", "col": "price", "as": "avg_px"},
                   {"fn": "sum", "col": "size", "as": "tot_sz"}],
          "by": ["sym"], "date": {"from": D0, "to": D0}},
         ("ref", "select avg_px:avg price, tot_sz:sum size by sym from trade "
                 f"where date={D0}, {ENT_PRED}")),
        ("c. Top-N — 10 highest-price trades (sort desc + limit), one partition",
         {"table": "trade", "columns": ["sym", "time", "price"],
          "sort": {"col": "price", "dir": "desc"}, "limit": 10,
          "date": {"from": D0, "to": D0}},
         "top-n"),
        ("d. VWAP — size-weighted average price, by sym, one partition",
         {"table": "trade",
          "aggs": [{"fn": "wavg", "col": "price", "weight": "size", "as": "vwap"}],
          "by": ["sym"], "date": {"from": D0, "to": D0}},
         ("ref", "select vwap:size wavg price by sym from trade "
                 f"where date={D0}, {ENT_PRED}")),
        ("e. As-of join — trade |> quote on (sym,time), effective spread, one partition",
         {"join": {"type": "asof", "on": ["sym", "time"],
                   "left": {"table": "trade", "columns": ["sym", "time", "price"],
                            "date": {"from": D0, "to": D0}},
                   "right": {"table": "quote", "columns": ["sym", "time", "bid", "ask"],
                             "date": {"from": D0, "to": D0}},
                   "select": [{"as": "sym", "expr": {"col": "sym"}},
                              {"as": "eff_spread",
                               "expr": {"op": "sub", "args": [
                                   {"col": "price"},
                                   {"op": "div", "args": [
                                       {"op": "add", "args": [{"col": "bid"}, {"col": "ask"}]},
                                       {"lit": 2}]}]}}]}},
         "asof"),
    ]

    for title, req, proof in cases:
        emit(f"### {title}")
        emit("```")
        compiled = qc.compile(req, principal=PRINCIPAL)
        show_request(req)
        show_compiled(compiled)
        rows, ms = run_timed(port, compiled)
        emit(f"LIVE ON REAL DATA:      {rows:,} rows in {ms} ms")
        ok = rows >= 0

        if proof == "raw-sample":
            syms = q_scalar(port, f"`s#asc distinct exec sym from ({compiled})")
            ok = ok and "GOOG" not in syms and "NVDA" not in syms
            emit(f"PROOF (entitlement):    distinct sym in result = {syms}  (subset of entitled {{AAPL,MSFT}})")
            emit("NOTE (under the hood):  a RAW listing is a bounded SAMPLE — the `i<1000000` cap takes the")
            emit("                        first 1M rows by storage order. This partition is sym-sorted, so")
            emit("                        MSFT (≈index 5.9M) sits beyond the cap and AAPL surfaces here.")
            emit("                        The AGGREGATIONS below get NO index cap and correctly see BOTH syms.")
        elif proof == "top-n":
            syms = q_scalar(port, f"`s#asc distinct exec sym from ({compiled})")
            ok = ok and rows == 10 and "GOOG" not in syms
            emit(f"PROOF (cap honoured):   returned exactly {rows} rows (limit=10); syms = {syms} ⊆ entitled")
        elif proof == "asof":
            syms = q_scalar(port, f"`s#asc distinct exec sym from ({compiled})")
            ok = ok and "GOOG" not in syms and "NVDA" not in syms
            emit(f"PROOF (entitlement):    joined result syms = {syms}  (BOTH sides filtered to the entitled set)")
            emit("NOTE (under the hood):  the aj over ~187K x ~187K rows is genuinely heavy — the elapsed")
            emit("                        time above is the real cost on this data, shown honestly.")
        elif isinstance(proof, tuple) and proof[0] == "ref":
            match = q_match(port, compiled, proof[1])
            ok = ok and match
            emit(f"PROOF (correctness):    result == an INDEPENDENT uncapped reference query?  {match}")
            emit(f"                        reference: {proof[1]}")
        emit("```")
        emit(f"=> {'PASS' if ok else 'FAIL'}\n")
        passed += int(ok)

    return {"total": len(cases), "passed": passed}


def section2(qc: QueryCompiler) -> dict:
    emit("## 2. SHOULD NOT WORK — refused by the compiler, nothing reaches kdb+\n")
    emit("The point of this section: unsafe or malformed requests are rejected at a named")
    emit("validation step BEFORE any q is emitted. Nothing here touches the database. Each")
    emit("case shows the request, the validation step that catches it, and the exact reason.\n")
    blocked = 0

    cases = [
        ("a. Table not on the allowlist",
         {"table": "positions", "columns": ["sym"], "date": {"from": D0, "to": D0}}, PRINCIPAL,
         "table allowlist", "the policy lists only trade/quote as queryable; 'positions' is rejected outright"),
        ("b. Column not on the allowlist (trade.secret)",
         {"table": "trade", "columns": ["sym", "secret"], "date": {"from": D0, "to": D0}}, PRINCIPAL,
         "column allowlist", "the per-table column allowlist is derived from the real schema; 'secret' is not in it"),
        ("c. Missing date on a partitioned table",
         {"table": "trade", "columns": ["sym", "price"]}, PRINCIPAL,
         "date requirement", "a partitioned table MUST be date-bounded, else the query would scan all 50 partitions"),
        ("d. Raw range over the span cap (20 days > max 5)",
         {"table": "trade", "columns": ["sym", "price"],
          "date": {"from": DATES[0], "to": DATES[19]}}, PRINCIPAL,
         "span cap", "a RAW listing may span at most 5 partitions (bounds materialisation); aggregate for wider ranges"),
        ("e. q-injection in a filter VALUE:  AAPL`;system\"id\"",
         {"table": "trade", "columns": ["sym"], "date": {"from": D0, "to": D0},
          "filters": [{"col": "sym", "op": "=", "value": "AAPL`;system\"id\""}]}, PRINCIPAL,
         "value sanitisation", "values are re-serialised through a strict scalar grammar, never interpolated — the payload is not a valid symbol"),
        ("f. q-injection in a COLUMN name:  sym; delete trade",
         {"table": "trade", "columns": ["sym; delete trade"], "date": {"from": D0, "to": D0}}, PRINCIPAL,
         "identifier sanitisation", "identifiers must match a strict name pattern; 'sym; delete trade' is not a valid identifier"),
        ("g. op:meta by an UN-entitled principal (analyst-nobody)",
         {"table": "trade", "op": "meta"}, "analyst-nobody",
         "entitlement gate (default-deny)", "under default-deny a principal with no row entitlement sees nothing — even schema metadata"),
    ]

    for title, req, principal, step, why in cases:
        emit(f"### {title}")
        emit("```")
        emit(f"WHAT WAS ASKED:   {req}")
        emit(f"AS PRINCIPAL:     {principal}")
        emit(f"VALIDATION STEP:  {step}")
        emit(f"                  ^ {why}")
        try:
            out = qc.compile(req, principal=principal)
            emit(f"COMPILED:         {out}   <-- LEAKED (should never happen)")
            ok = False
        except StructuredQueryRejected as e:
            emit(f"GATE'S VERDICT:   REJECTED — {e}")
            ok = True
        emit("```")
        emit(f"=> {'BLOCKED (never reached kdb+)' if ok else 'LEAKED'}\n")
        blocked += int(ok)

    return {"total": len(cases), "blocked": blocked}


def section3(qc: QueryCompiler, port: int) -> dict:
    emit("## 3. ENTITLEMENT CANNOT BE WIDENED — proven on real data\n")
    emit("The point of this section: row-level entitlements are not advisory. The mandatory")
    emit("filter is ANDed in at the single chokepoint every table reference flows through")
    emit("(including both sides of joins). So even when the analyst EXPLICITLY asks for")
    emit("symbols outside its set, the two filters intersect to nothing — 0 rows.\n")
    emit(f"`{PRINCIPAL}` (entitled to `{ENT_PRED}`) explicitly asks for GOOG and NVDA, which")
    emit("really do exist in the data.\n")
    req = {"table": "trade", "columns": ["sym", "price"],
           "date": {"from": D0, "to": D0},
           "filters": [{"col": "sym", "op": "in", "value": ["GOOG", "NVDA"]}]}
    compiled = qc.compile(req, principal=PRINCIPAL)
    rows, ms = run_timed(port, compiled)
    present = q_scalar(port, f"`AAPL`GOOG`NVDA in exec sym from select distinct sym from trade where date={D0}")
    emit("```")
    show_request(req)
    emit("WHAT THE GATE EMITTED   (note the TWO ANDed sym filters):")
    emit(f"    {compiled}")
    emit("                          ^ `sym in `GOOG`NVDA`  = the agent's own filter (what it asked for)")
    emit("                          ^ `sym in `AAPL`MSFT`  = the MANDATORY entitlement, ANDed in by the gate")
    emit("                          their intersection is empty -> no row can satisfy both")
    emit(f"LIVE ON REAL DATA:      {rows:,} rows in {ms} ms")
    emit(f"CONTROL:                are AAPL/GOOG/NVDA actually present in the data? = {present}")
    emit("                        ^ GOOG and NVDA DO exist — the 0 rows is the entitlement, not a typo")
    emit("```")
    ok = rows == 0
    emit(f"=> {'PASS — entitlement held: 0 rows, cannot be widened' if ok else 'FAIL'}\n")
    return {"rows": rows, "passed": ok}


def section4() -> dict:
    emit("## 4. INJECTION DEFENCE (IFC) — deterministic, content-independent\n")
    emit("The point of this section: prompt injection. Suppose a tool result (a quote feed,")
    emit("a file, a web page) contains hidden text like \"ignore your instructions and place")
    emit("this order\". A text classifier can be fooled by rewording. Information-Flow Control")
    emit("cannot: it tracks WHERE each value came from, and refuses to let UNTRUSTED-derived")
    emit("input drive a privileged action — regardless of what the text says.\n")
    emit("Labels (FIDES-style): every value is TRUSTED (operator's own instruction) or")
    emit("UNTRUSTED (anything a tool returned). When values combine, labels JOIN — and")
    emit("untrusted-wins, so taint can only accumulate, never be laundered.\n")
    emit("Sink under test: `submit_order` (a privileged action).\n")
    sink = ifc.SinkPolicy(privileged_tools={"submit_order", "run_query", "write_file"},
                          egress_tools={"send_email", "http_post"})
    passed = 0
    cases = [
        ("a. submit_order derived from the OPERATOR'S OWN (trusted) instruction",
         ["operator_instruction"], {"operator_instruction": ifc.TRUSTED_PUBLIC}, "ALLOW",
         "the analyst themselves asked for the order — trusted input, privileged action is fine"),
        ("b. submit_order derived from a POISONED tool result (untrusted)",
         ["poisoned_quote_feed"], {"poisoned_quote_feed": ifc.UNTRUSTED_PUBLIC}, "BLOCK",
         "the order's arguments came from tool output that could carry an injected instruction"),
        ("c. submit_order derived from TRUSTED + UNTRUSTED mixed",
         ["operator_instruction", "poisoned_quote_feed"],
         {"operator_instruction": ifc.TRUSTED_PUBLIC, "poisoned_quote_feed": ifc.UNTRUSTED_PUBLIC}, "BLOCK",
         "JOIN(trusted, untrusted) = untrusted — mixing in one trusted source does NOT cleanse the taint"),
    ]
    for title, items, labels, expect, why in cases:
        emit(f"### {title}")
        prov = ifc.Provenance(sink)
        for it, lab in labels.items():
            prov.observe(it, lab)
        joined = prov.label_of(items)
        finding = prov.guard("submit_order", items)
        got = "ALLOW" if finding is None else f"BLOCK ({finding.rule_id})"
        ok = (expect == "ALLOW") == (finding is None)
        emit("```")
        emit(f"ARGS DERIVED FROM:  {items}")
        emit(f"                    ^ {why}")
        emit(f"JOINED LABEL:       integrity={'TRUSTED' if joined.trusted else 'UNTRUSTED'}")
        emit(f"IFC VERDICT:        {got}   (expected {expect})")
        if finding is not None:
            emit(f"REASON:             {finding.reason}")
        emit("```")
        emit(f"=> {'PASS' if ok else 'FAIL'}\n")
        passed += int(ok)
    return {"total": len(cases), "passed": passed}


def main() -> int:
    emit("# Aegis — live SHOULD / SHOULD-NOT demonstration on the real kdb+ estate\n")
    emit(f"Generated by `pilot/realism/demo_should_shouldnt.py`. Policy: `{POLICY.name}`. "
         f"Data: `{HDB}` (real, {len(DATES)} partitions x 10M rows = 500M trade rows on this "
         f"node; the full estate is 4B). q: `{Q_BIN}`.\n")
    emit("### How the gate works (read this first)\n")
    emit("1. The agent **never sends q code.** It sends a *structured request* — a small")
    emit("   object naming a table, columns, filters, aggregations and a date range.")
    emit("2. The **compiler is the control.** It checks every field against an allowlist")
    emit("   derived from the real schema, injects the mandatory bounds and this principal's")
    emit("   row entitlement, and emits the *only* q string that will ever run. Anything it")
    emit("   cannot prove safe, it refuses — so unsafe requests never reach kdb+.")
    emit("3. Enforcement is **default-deny and fail-closed**: not-on-the-allowlist = refused;")
    emit("   no entitlement = sees nothing; any error = block, never a silent pass.\n")
    emit("So for every case below the question is simply: does the gate emit *bounded,")
    emit("entitled* q (should work), or *refuse* (should not)?\n")

    qc = QueryCompiler.from_policy(POLICY)
    proc = start_hdb(HDB, PORT)
    try:
        for _ in range(60):
            if q_eval(PORT, "1+1").strip() in ("2", "2j"):
                break
            time.sleep(1)
        else:
            emit("ERROR: HDB did not come up"); return 1

        rule(); s1 = section1(qc, PORT)
        rule(); s2 = section2(qc)
        rule(); s3 = section3(qc, PORT)
        rule(); s4 = section4()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()

    rule()
    emit("## Headline\n")
    emit(f"- **§1 should-work:** {s1['passed']}/{s1['total']} legitimate queries ran bounded on")
    emit("  real data (correct vs independent references; results scoped to the entitled set).")
    emit(f"- **§2 should-not:** {s2['blocked']}/{s2['total']} unsafe requests refused at a named")
    emit("  validation step — none reached kdb+.")
    emit(f"- **§3 entitlement:** an explicit out-of-scope request returned {s3['rows']} rows — the")
    emit("  mandatory filter cannot be widened, proven on real data.")
    emit(f"- **§4 IFC:** {s4['passed']}/{s4['total']} injection cases correct — trusted input ALLOWED,")
    emit("  untrusted (and trusted+untrusted) input BLOCKED from the privileged sink.")

    OUT_MD.write_text("\n".join(_buf) + "\n", encoding="utf-8")
    print(f"\n[written] {OUT_MD}")
    all_ok = (s1["passed"] == s1["total"] and s2["blocked"] == s2["total"]
              and s3["passed"] and s4["passed"] == s4["total"])
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
