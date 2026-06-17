#!/usr/bin/env python3
"""Aegis guardrail demo as a live HTML window — the browser counterpart to
demo_should_shouldnt.py. Buttons hit a tiny local backend that, for real and on
the spot against the 4-billion-row kdb+ estate:
  * compiles a structured request through the REAL QueryCompiler (loaded from
    pilot/realism/policy.realism.demo.json) and executes it on a live HDB;
  * shows the exact rejection for unsafe / malformed / injected requests;
  * proves the row entitlement cannot be widened;
  * runs the IFC veto (aegis.ifc) for the prompt-injection cases.

Everything is deterministic and needs no API.

Run:
    cd ~/guard && QHOME=/opt/kdb/4.1/2024.10.16 QLIC=/opt/kdb/QLIC \
        .venv/bin/python pilot/realism/demo_server.py            # http://localhost:8012/
"""
from __future__ import annotations

import json
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO))

from aegis.query_compiler import QueryCompiler, StructuredQueryRejected
from aegis import ifc
from pilot.realism.realism_soak import q_eval, q_match, start_hdb, available_dates, Q_BIN

POLICY = HERE / "policy.realism.demo.json"
HTML = HERE / "demo_web.html"
HDB = str(Path.home() / "aegis-hdb" / "fsp1" / "hdb")
PORT = 8012        # HTTP server
HDB_PORT = 8013    # the kdb+ HDB process (must differ from the HTTP port)
PRINCIPAL = "analyst-equities"
ENT_PRED = "sym in `AAPL`MSFT"

QC = QueryCompiler.from_policy(POLICY)
DATES = available_dates(HDB)
D0 = DATES[0]


def run_timed(q: str) -> tuple[int, int]:
    thunk = f"{{[] st:.z.p; res:({q}); (count res;`long$(.z.p-st)%1000000)}}[]"
    out = q_eval(HDB_PORT, thunk, timeout=300)
    nums = re.findall(r"-?\d+", out)
    return (-1, -1) if out.startswith("ERR") or len(nums) < 2 else (int(nums[0]), int(nums[1]))


def qscalar(expr: str) -> str:
    return q_eval(HDB_PORT, expr, timeout=300).strip()


def transforms(compiled: str) -> list:
    notes = []
    m = re.search(r"date within \S+ \S+|date=\d{4}\.\d{2}\.\d{2}", compiled)
    if m:
        notes.append(["partition bound", m.group(0), "restricts the scan to named date partitions, never the whole DB"])
    if ENT_PRED in compiled:
        notes.append(["entitlement filter", ENT_PRED, f"mandatory row filter for '{PRINCIPAL}', injected by the gate; the agent cannot set, remove, or widen it"])
    m = re.search(r"i<(\d+)", compiled)
    if m:
        notes.append(["materialisation cap", f"i<{m.group(1)}", "bounds rows read off disk per partition (raw listings only)"])
    m = re.search(r"(\d+) sublist", compiled)
    if m:
        notes.append(["result cap", f"{m.group(1)} sublist", "bounds the rows returned to the agent"])
    return notes


# ---- SHOULD WORK cases (compiled + executed live) ------------------------
SHOULD_WORK = {
    "filter": {"title": "Filtered raw select (size>500), one partition",
        "req": {"table": "trade", "columns": ["sym", "time", "price", "size"],
                "filters": [{"col": "size", "op": ">", "value": 500}], "date": {"from": D0, "to": D0}},
        "proof": "raw"},
    "agg": {"title": "Aggregation: avg price + total size by sym",
        "req": {"table": "trade", "aggs": [{"fn": "avg", "col": "price", "as": "avg_px"},
                {"fn": "sum", "col": "size", "as": "tot_sz"}], "by": ["sym"], "date": {"from": D0, "to": D0}},
        "proof": "ref", "ref": f"select avg_px:avg price, tot_sz:sum size by sym from trade where date={D0}, {ENT_PRED}"},
    "topn": {"title": "Top 10 highest-price trades (sort + limit)",
        "req": {"table": "trade", "columns": ["sym", "time", "price"], "sort": {"col": "price", "dir": "desc"},
                "limit": 10, "date": {"from": D0, "to": D0}}, "proof": "topn"},
    "vwap": {"title": "VWAP (size-weighted price) by sym",
        "req": {"table": "trade", "aggs": [{"fn": "wavg", "col": "price", "weight": "size", "as": "vwap"}],
                "by": ["sym"], "date": {"from": D0, "to": D0}},
        "proof": "ref", "ref": f"select vwap:size wavg price by sym from trade where date={D0}, {ENT_PRED}"},
    "asof": {"title": "As-of join trade |> quote, effective spread",
        "req": {"join": {"type": "asof", "on": ["sym", "time"],
                "left": {"table": "trade", "columns": ["sym", "time", "price"], "date": {"from": D0, "to": D0}},
                "right": {"table": "quote", "columns": ["sym", "time", "bid", "ask"], "date": {"from": D0, "to": D0}},
                "select": [{"as": "sym", "expr": {"col": "sym"}},
                           {"as": "eff_spread", "expr": {"op": "sub", "args": [{"col": "price"},
                            {"op": "div", "args": [{"op": "add", "args": [{"col": "bid"}, {"col": "ask"}]}, {"lit": 2}]}]}}]}},
        "proof": "asof"},
}

SHOULD_NOT = {
    "table": {"title": "Table not on the allowlist", "step": "table allowlist",
        "req": {"table": "positions", "columns": ["sym"], "date": {"from": D0, "to": D0}}, "p": PRINCIPAL},
    "column": {"title": "Column not on the allowlist (trade.secret)", "step": "column allowlist",
        "req": {"table": "trade", "columns": ["sym", "secret"], "date": {"from": D0, "to": D0}}, "p": PRINCIPAL},
    "nodate": {"title": "Missing date on a partitioned table", "step": "date requirement",
        "req": {"table": "trade", "columns": ["sym", "price"]}, "p": PRINCIPAL},
    "span": {"title": "Raw range over the span cap (20 days > max 5)", "step": "span cap",
        "req": {"table": "trade", "columns": ["sym", "price"], "date": {"from": DATES[0], "to": DATES[19]}}, "p": PRINCIPAL},
    "injval": {"title": "q-injection in a filter VALUE: AAPL`;system\"id\"", "step": "value sanitisation",
        "req": {"table": "trade", "columns": ["sym"], "date": {"from": D0, "to": D0},
                "filters": [{"col": "sym", "op": "=", "value": "AAPL`;system\"id\""}]}, "p": PRINCIPAL},
    "injcol": {"title": "q-injection in a COLUMN name: sym; delete trade", "step": "identifier sanitisation",
        "req": {"table": "trade", "columns": ["sym; delete trade"], "date": {"from": D0, "to": D0}}, "p": PRINCIPAL},
    "meta": {"title": "op:meta by an un-entitled principal", "step": "entitlement gate (default-deny)",
        "req": {"table": "trade", "op": "meta"}, "p": "analyst-nobody"},
}

IFC_CASES = {
    "trusted": {"title": "submit_order from the OPERATOR's own (trusted) instruction",
        "items": ["operator_instruction"], "labels": {"operator_instruction": "T"}, "expect": "ALLOW"},
    "untrusted": {"title": "submit_order from a POISONED tool result (untrusted)",
        "items": ["poisoned_feed"], "labels": {"poisoned_feed": "U"}, "expect": "BLOCK"},
    "mixed": {"title": "submit_order from TRUSTED + UNTRUSTED mixed",
        "items": ["operator_instruction", "poisoned_feed"],
        "labels": {"operator_instruction": "T", "poisoned_feed": "U"}, "expect": "BLOCK"},
}
_SINK = ifc.SinkPolicy(privileged_tools={"submit_order", "run_query", "write_file"},
                       egress_tools={"send_email", "http_post"})


def do_should_work(key: str) -> dict:
    c = SHOULD_WORK[key]
    compiled = QC.compile(c["req"], principal=PRINCIPAL)
    rows, ms = run_timed(compiled)
    out = {"title": c["title"], "request": c["req"], "compiled": compiled,
           "transforms": transforms(compiled), "rows": rows, "ms": ms}
    if c["proof"] == "raw":
        syms = qscalar(f"`s#asc distinct exec sym from ({compiled})")
        out["proof"] = f"distinct sym in result = {syms} (subset of entitled {{AAPL,MSFT}})"
        out["note"] = ("a raw listing is a bounded sample: the i<1000000 cap takes the first 1M rows "
                       "by storage order. This partition is sym-sorted, so MSFT sits beyond the cap and "
                       "AAPL surfaces here. The aggregations get no index cap and see both syms.")
    elif c["proof"] == "topn":
        syms = qscalar(f"`s#asc distinct exec sym from ({compiled})")
        out["proof"] = f"returned exactly {rows} rows (limit honoured); syms = {syms}"
    elif c["proof"] == "asof":
        syms = qscalar(f"`s#asc distinct exec sym from ({compiled})")
        out["proof"] = f"joined result syms = {syms} (both sides entitlement-filtered)"
        out["note"] = "the aj over ~187K x ~187K rows is genuinely heavy; the elapsed time is the real cost, shown honestly."
    elif c["proof"] == "ref":
        out["proof"] = f"matches an INDEPENDENT uncapped reference query: {q_match(HDB_PORT, compiled, c['ref'])}"
        out["ref"] = c["ref"]
    out["pass"] = rows >= 0
    return out


def do_should_not(key: str) -> dict:
    c = SHOULD_NOT[key]
    try:
        compiled = QC.compile(c["req"], principal=c["p"])
        return {"title": c["title"], "request": c["req"], "principal": c["p"], "step": c["step"],
                "blocked": False, "leaked": compiled}
    except StructuredQueryRejected as e:
        return {"title": c["title"], "request": c["req"], "principal": c["p"], "step": c["step"],
                "blocked": True, "reason": str(e)}


def do_entitlement() -> dict:
    req = {"table": "trade", "columns": ["sym", "price"], "date": {"from": D0, "to": D0},
           "filters": [{"col": "sym", "op": "in", "value": ["GOOG", "NVDA"]}]}
    compiled = QC.compile(req, principal=PRINCIPAL)
    rows, ms = run_timed(compiled)
    present = qscalar(f"`AAPL`GOOG`NVDA in exec sym from select distinct sym from trade where date={D0}")
    return {"request": req, "compiled": compiled, "rows": rows, "ms": ms, "present": present, "pass": rows == 0}


def do_ifc(key: str) -> dict:
    c = IFC_CASES[key]
    prov = ifc.Provenance(_SINK)
    for it, lab in c["labels"].items():
        prov.observe(it, ifc.TRUSTED_PUBLIC if lab == "T" else ifc.UNTRUSTED_PUBLIC)
    finding = prov.guard("submit_order", c["items"])
    joined = prov.label_of(c["items"])
    got = "ALLOW" if finding is None else "BLOCK"
    return {"title": c["title"], "items": c["items"], "expect": c["expect"], "verdict": got,
            "integrity": "TRUSTED" if joined.trusted else "UNTRUSTED",
            "rule": finding.rule_id if finding else None,
            "reason": finding.reason if finding else None,
            "pass": (c["expect"] == "ALLOW") == (finding is None)}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, HTML.read_bytes(), "text/html; charset=utf-8")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._send(400, json.dumps({"error": "bad request"}))
        try:
            if self.path == "/api/should_work":
                self._send(200, json.dumps(do_should_work(req["case"])))
            elif self.path == "/api/should_not":
                self._send(200, json.dumps(do_should_not(req["case"])))
            elif self.path == "/api/entitlement":
                self._send(200, json.dumps(do_entitlement()))
            elif self.path == "/api/ifc":
                self._send(200, json.dumps(do_ifc(req["case"])))
            else:
                self._send(404, json.dumps({"error": "no such endpoint"}))
        except Exception as e:
            self._send(200, json.dumps({"error": f"{type(e).__name__}: {e}"}))


def main() -> int:
    proc = start_hdb(HDB, HDB_PORT)
    for _ in range(60):
        if q_eval(HDB_PORT, "1+1").strip() in ("2", "2j"):
            break
        time.sleep(1)
    else:
        print("HDB did not come up"); return 1
    print(f"[aegis-demo] HDB up ({len(DATES)} partitions). LIVE on http://localhost:{PORT}/")
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
