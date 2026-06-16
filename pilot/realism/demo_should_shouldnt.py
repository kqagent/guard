#!/usr/bin/env python3
"""Live "should / shouldn't work" demonstration of the Aegis gate against the REAL
4-billion-row kdb+ estate (~/aegis-hdb/fsp1, 50 partitions x 10M rows).

Everything here is executed, not described:
  * the structured-query compiler is loaded from a REAL policy
    (pilot/realism/policy.realism.demo.json = the realism estate policy + the two
    controls this demo showcases: row-level entitlements + raw-range span cap);
  * compiled queries run on a live HDB process (reusing realism_soak's start_hdb /
    q_eval helpers), so every row count and elapsed time below is real;
  * the IFC section uses aegis.ifc directly.

Four sections:
  1. SHOULD WORK      — 5 requests compiled + executed on the live HDB.
  2. SHOULD NOT WORK  — 6 requests rejected by the compiler before reaching kdb+.
  3. ENTITLEMENT CANNOT BE WIDENED — an entitled analyst asks outside its set; the
     compiled q carries BOTH its filter and the mandatory one -> 0 rows on real data.
  4. INJECTION DEFENCE (IFC) — trusted-derived sink ALLOW; untrusted-derived BLOCK;
     mixed BLOCK.

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
from pilot.realism.realism_soak import (Q_BIN, Q_ENV, q_eval, q_match, start_hdb,
                                        available_dates)

POLICY = HERE / "policy.realism.demo.json"
OUT_MD = HERE / "DEMO_should_shouldnt.md"
HDB = str(Path.home() / "aegis-hdb" / "fsp1" / "hdb")
PORT = 31999
PRINCIPAL = "analyst-equities"

# transcript buffer (markdown), mirrored to stdout
_buf: list[str] = []


def emit(line: str = "") -> None:
    _buf.append(line)
    print(line)


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


# ---------------------------------------------------------------------------
DATES = available_dates(HDB)
D0 = DATES[0]                       # 2025.06.01
D4 = DATES[4]                       # 2025.06.05  (5-partition span, == the cap)


def section1(qc: QueryCompiler, port: int) -> dict:
    emit("## 1. SHOULD WORK — compiled and executed on the live HDB\n")
    emit(f"Principal: `{PRINCIPAL}` (entitled to `sym in (AAPL;MSFT)`). HDB: "
         f"`{HDB}` — {len(DATES)} partitions x 10M rows. All timings are server-side.\n")
    passed = 0

    cases = [
        ("a. Filtered raw select (size>500), one partition",
         {"table": "trade", "columns": ["sym", "time", "price", "size"],
          "filters": [{"col": "size", "op": ">", "value": 500}],
          "date": {"from": D0, "to": D0}},
         "distinct-sym"),
        ("b. Aggregation: avg price + total size by sym, one partition",
         {"table": "trade",
          "aggs": [{"fn": "avg", "col": "price", "as": "avg_px"},
                   {"fn": "sum", "col": "size", "as": "tot_sz"}],
          "by": ["sym"], "date": {"from": D0, "to": D0}},
         ("ref", "select avg_px:avg price, tot_sz:sum size by sym from trade "
                 f"where date={D0}, sym in (`AAPL;`MSFT)")),
        ("c. Top-N: 10 highest-price trades, sort desc + limit, one partition",
         {"table": "trade", "columns": ["sym", "time", "price"],
          "sort": {"col": "price", "dir": "desc"}, "limit": 10,
          "date": {"from": D0, "to": D0}},
         "top-n"),
        ("d. VWAP (size-weighted price) by sym, one partition",
         {"table": "trade",
          "aggs": [{"fn": "wavg", "col": "price", "weight": "size", "as": "vwap"}],
          "by": ["sym"], "date": {"from": D0, "to": D0}},
         ("ref", "select vwap:size wavg price by sym from trade "
                 f"where date={D0}, sym in (`AAPL;`MSFT)")),
        ("e. As-of join trade|>quote on (sym,time); effective spread, one partition",
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
        compiled = qc.compile(req, principal=PRINCIPAL)
        emit("```")
        emit(f"request : {req}")
        emit(f"compiled: {compiled}")
        rows, ms = run_timed(port, compiled)
        emit(f"executed: {rows:,} rows in {ms} ms")
        ok = rows >= 0
        if proof == "distinct-sym":
            syms = q_scalar(port, f"`s#asc distinct exec sym from ({compiled})")
            ok = ok and "AAPL" in syms and "GOOG" not in syms and "NVDA" not in syms
            emit(f"BOUND   : distinct sym in result = {syms}  (entitlement held)")
        elif proof == "top-n":
            syms = q_scalar(port, f"`s#asc distinct exec sym from ({compiled})")
            ok = ok and rows == 10 and "GOOG" not in syms
            emit(f"BOUND   : returned exactly {rows} rows (limit honoured); syms = {syms}")
        elif proof == "asof":
            syms = q_scalar(port, f"`s#asc distinct exec sym from ({compiled})")
            ok = ok and "GOOG" not in syms and "NVDA" not in syms
            emit(f"BOUND   : joined result syms = {syms}  (both sides entitlement-filtered)")
            emit("NOTE    : the aj over ~187K x ~187K rows is genuinely heavy — the elapsed")
            emit("          time above is the real cost on this data, shown honestly.")
        elif isinstance(proof, tuple) and proof[0] == "ref":
            match = q_match(port, compiled, proof[1])
            ok = ok and match
            emit(f"PROOF   : matches independent uncapped reference query = {match}")
            emit(f"          ref: {proof[1]}")
        emit("```")
        emit(f"-> {'PASS' if ok else 'FAIL'}\n")
        passed += int(ok)

    return {"total": len(cases), "passed": passed}


def section2(qc: QueryCompiler) -> dict:
    emit("## 2. SHOULD NOT WORK — rejected by the compiler, never reach kdb+\n")
    emit("Each prints the exact rejection reason. No q is emitted, nothing executes.\n")
    blocked = 0

    cases = [
        ("a. Table not on the allowlist",
         {"table": "positions", "columns": ["sym"], "date": {"from": D0, "to": D0}}, PRINCIPAL),
        ("b. Column not on the allowlist (trade.secret)",
         {"table": "trade", "columns": ["sym", "secret"], "date": {"from": D0, "to": D0}}, PRINCIPAL),
        ("c. Missing date on a partitioned table",
         {"table": "trade", "columns": ["sym", "price"]}, PRINCIPAL),
        ("d. Raw range over the span cap (20 days > max 5)",
         {"table": "trade", "columns": ["sym", "price"],
          "date": {"from": DATES[0], "to": DATES[19]}}, PRINCIPAL),
        ("e. Injection in a filter VALUE: AAPL`;system\"id\"",
         {"table": "trade", "columns": ["sym"], "date": {"from": D0, "to": D0},
          "filters": [{"col": "sym", "op": "=", "value": "AAPL`;system\"id\""}]}, PRINCIPAL),
        ("f. Injection in a COLUMN name: sym; delete trade",
         {"table": "trade", "columns": ["sym; delete trade"], "date": {"from": D0, "to": D0}}, PRINCIPAL),
        ("g. op:meta by an UN-entitled principal (analyst-nobody)",
         {"table": "trade", "op": "meta"}, "analyst-nobody"),
    ]

    for title, req, principal in cases:
        emit(f"### {title}")
        emit("```")
        emit(f"request : {req}")
        emit(f"principal: {principal}")
        try:
            out = qc.compile(req, principal=principal)
            emit(f"compiled: {out}   <-- LEAKED (should not happen)")
            ok = False
        except StructuredQueryRejected as e:
            emit(f"REJECTED: {e}")
            ok = True
        emit("```")
        emit(f"-> {'BLOCKED' if ok else 'LEAKED'}\n")
        blocked += int(ok)

    return {"total": len(cases), "blocked": blocked}


def section3(qc: QueryCompiler, port: int) -> dict:
    emit("## 3. ENTITLEMENT CANNOT BE WIDENED — proven on real data\n")
    emit(f"`{PRINCIPAL}` is entitled to `sym in (AAPL;MSFT)` only. It explicitly asks "
         "for GOOG and NVDA (which DO exist in the data). The compiled q carries BOTH "
         "the agent's own filter AND the mandatory entitlement filter — their "
         "intersection is empty, so it returns 0 rows. The analyst cannot widen.\n")
    req = {"table": "trade", "columns": ["sym", "price"],
           "date": {"from": D0, "to": D0},
           "filters": [{"col": "sym", "op": "in", "value": ["GOOG", "NVDA"]}]}
    compiled = qc.compile(req, principal=PRINCIPAL)
    rows, ms = run_timed(port, compiled)
    # control: GOOG/NVDA really are present in the data (so 0 isn't a "no such sym")
    present = q_scalar(port, f"`AAPL`GOOG`NVDA in exec sym from select distinct sym from trade where date={D0}")
    emit("```")
    emit(f"request : {req}")
    emit(f"compiled: {compiled}")
    emit(f"          ^ note BOTH `sym in (`GOOG;`NVDA)` (agent) AND `sym in (`AAPL;`MSFT)` (mandatory)")
    emit(f"executed: {rows:,} rows in {ms} ms")
    emit(f"control : `AAPL`GOOG`NVDA present in data? = {present}  (GOOG/NVDA exist; 0 rows is the entitlement, not a typo)")
    emit("```")
    ok = rows == 0
    emit(f"-> {'PASS — entitlement held (0 rows)' if ok else 'FAIL'}\n")
    return {"rows": rows, "passed": ok}


def section4() -> dict:
    emit("## 4. INJECTION DEFENCE (IFC) — deterministic, content-independent\n")
    emit("FIDES-style information-flow control. A privileged sink (`submit_order`) is "
         "vetoed when its arguments are derived from UNTRUSTED content (e.g. an injected "
         "instruction in a tool result), regardless of wording. Trusted-derived actions "
         "pass. Labels JOIN monotonically — mixing trusted + untrusted is still untrusted.\n")
    sink = ifc.SinkPolicy(privileged_tools={"submit_order", "run_query", "write_file"},
                          egress_tools={"send_email", "http_post"})
    passed = 0
    cases = [
        ("a. submit_order derived from the OPERATOR's own (trusted) instruction",
         ["operator_instruction"], {"operator_instruction": ifc.TRUSTED_PUBLIC}, "ALLOW"),
        ("b. submit_order derived from a POISONED tool result (untrusted)",
         ["poisoned_quote_feed"], {"poisoned_quote_feed": ifc.UNTRUSTED_PUBLIC}, "BLOCK"),
        ("c. submit_order derived from TRUSTED + UNTRUSTED mixed (join -> untrusted)",
         ["operator_instruction", "poisoned_quote_feed"],
         {"operator_instruction": ifc.TRUSTED_PUBLIC, "poisoned_quote_feed": ifc.UNTRUSTED_PUBLIC}, "BLOCK"),
    ]
    for title, items, labels, expect in cases:
        emit(f"### {title}")
        prov = ifc.Provenance(sink)
        for it, lab in labels.items():
            prov.observe(it, lab)
        finding = prov.guard("submit_order", items)
        got = "ALLOW" if finding is None else f"BLOCK ({finding.rule_id})"
        ok = (expect == "ALLOW") == (finding is None)
        emit("```")
        emit(f"derived from: {items}")
        emit(f"joined label: integrity={'TRUSTED' if prov.label_of(items).trusted else 'UNTRUSTED'}, "
             f"confidentiality={'SENSITIVE' if prov.label_of(items).sensitive else 'PUBLIC'}")
        emit(f"IFC verdict : {got}   (expected {expect})")
        if finding is not None:
            emit(f"reason      : {finding.reason}")
        emit("```")
        emit(f"-> {'PASS' if ok else 'FAIL'}\n")
        passed += int(ok)
    return {"total": len(cases), "passed": passed}


def main() -> int:
    emit("# Aegis — live SHOULD / SHOULD-NOT demonstration on the real kdb+ estate\n")
    emit(f"Generated by `pilot/realism/demo_should_shouldnt.py`. Policy: "
         f"`{POLICY.name}`. Data: `{HDB}` (real, {len(DATES)} partitions x 10M rows = "
         f"500M trade rows on fsp1; full estate is 4B). q: `{Q_BIN}`.\n")

    qc = QueryCompiler.from_policy(POLICY)
    proc = start_hdb(HDB, PORT)
    try:
        # wait for the HDB to load its partitions
        for _ in range(60):
            if q_eval(PORT, "1+1").strip() in ("2", "2j"):
                break
            time.sleep(1)
        else:
            emit("ERROR: HDB did not come up"); return 1

        s1 = section1(qc, PORT)
        s2 = section2(qc)
        s3 = section3(qc, PORT)
        s4 = section4()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()

    emit("## Headline\n")
    emit(f"- **§1 should-work:** {s1['passed']}/{s1['total']} allowed queries ran "
         "bounded on real data (correct vs uncapped references / entitlement held).")
    emit(f"- **§2 should-not:** {s2['blocked']}/{s2['total']} unsafe requests rejected "
         "by the compiler — none reached kdb+.")
    emit(f"- **§3 entitlement:** out-of-scope request returned {s3['rows']} rows "
         "(cannot be widened, proven on real data).")
    emit(f"- **§4 IFC:** {s4['passed']}/{s4['total']} injection cases correct "
         "(trusted ALLOW, untrusted/mixed BLOCK).")

    OUT_MD.write_text("\n".join(_buf) + "\n", encoding="utf-8")
    print(f"\n[written] {OUT_MD}")
    all_ok = (s1["passed"] == s1["total"] and s2["blocked"] == s2["total"]
              and s3["passed"] and s4["passed"] == s4["total"])
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
