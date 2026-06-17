#!/usr/bin/env python3
"""Aegis — the single, presentable web demo of the whole gate, live on the real
kdb+ estate. One server + one page (demo.html) that walks an audience through
every capability end to end, with NOTHING pre-recorded:

  1. Structured query   — the compiler emits bounded, date-first, capped,
     entitlement-filtered q; real rows back, with honest timing.
  2. Row entitlements    — the analyst sees only its entitled rows; an explicit
     out-of-scope request returns 0; the compiled q carries BOTH the agent
     filter and the mandatory entitlement.
  3. Free-form q         — a hand-written query is LIFTED and RECOMPILED through
     the same compiler (allowlist-on-parse); the raw q is never executed. Shows
     a date-second query normalised to date-first (no OOM) and dangerous /
     non-liftable q rejected, naming WHICH layer caught it (lifter vs compiler).
  4. Safety + resource   — dangerous ops are inexpressible; a would-be unbounded
     scan is bounded by the materialisation cap, so it cannot OOM the box.
  5. Injection defence   — an action derived from untrusted tool output is
     blocked before a privileged sink (IFC); the same action from trusted
     input is allowed. Deterministic, content-independent.
  6. The record          — the signed policy (tamper => fail-closed) and a WORM,
     hash-chained audit line PER DECISION; the gate runs out-of-process behind
     OS confinement ("the only wire out is the gate").

Every query route goes through the ONE chokepoint, aegis.query_gate.QueryGate:
the structured tool compiles the request; the free-form tool lifts+recompiles.
Both return only the trusted compiler's bounded q — or block, fail-closed.

Run:
    cd ~/guard && QHOME=/opt/kdb/4.1/2024.10.16 QLIC=/opt/kdb/QLIC \\
        .venv/bin/python pilot/demo/demo_app.py          # http://localhost:8012/
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

from aegis import ifc, signing
from aegis.audit import AuditLog
from aegis.freeform_q import FreeformRejected, advisories, lift
from aegis.model import Action, Decision, Effect, Finding
from aegis.query_compiler import QueryCompiler, StructuredQueryRejected
from aegis.query_gate import QueryGate
from pilot.realism.realism_soak import available_dates, q_eval, q_match, start_hdb

# The demo reuses the realism policy (column allowlist derived from meta on the
# real tables) PLUS the two showcase controls: row entitlements + span cap.
POLICY = REPO / "pilot" / "realism" / "policy.realism.demo.json"
HTML = HERE / "demo.html"
HDB = str(Path.home() / "aegis-hdb" / "fsp1" / "hdb")
PORT = 8012        # HTTP server
HDB_PORT = 8013    # the kdb+ HDB process (must differ from the HTTP port)
PRINCIPAL = "analyst-equities"
ENT_PRED = "sym in `AAPL`MSFT"
CAP = 1_000_000    # query_proxy.max_rows in the policy

# The ONE chokepoint. Structured tool -> compile; free-form tool -> lift+recompile.
QC = QueryCompiler.from_policy(POLICY)
GATE = QueryGate(QC, allow_freeform=True)
STRUCTURED_TOOL = "run_structured_query"
FREEFORM_TOOL = "run_query"

DATES = available_dates(HDB)
D0 = DATES[0]

# --- WORM audit: one hash-chained line per decision, mirrored + anchored ------
AUDIT_DIR = HERE / ".aegis-demo"
AUDIT = AuditLog(AUDIT_DIR / "audit.jsonl",
                 mirror_path=AUDIT_DIR / "audit.mirror.jsonl",
                 anchor_path=AUDIT_DIR / "audit.anchor.json")

# --- signed policy: sign at startup, pin the public key, verify (fail-closed) -
_ALGO = "ed25519" if signing.have_ed25519() else "hmac-sha256"
_PRIV, _PUB = signing.generate_keypair(_ALGO)
_POLICY_BYTES = POLICY.read_bytes()
_SIG = signing.sign(_POLICY_BYTES, _PRIV, _ALGO)


def _audit(tool: str, tinput: dict, effect: Effect, rule: str | None, reason: str | None,
           principal: str = PRINCIPAL) -> None:
    """Append ONE WORM, hash-chained audit line for this decision."""
    findings = [Finding(rule_id=rule, effect=effect, reason=reason or "", pack="demo")] if rule else []
    AUDIT.record(Action(tool=tool, tool_input=tinput, principal=principal),
                 Decision(effect=effect, findings=findings), principal=principal)


def run_timed(q: str) -> tuple[int, int]:
    """Execute q on the live HDB, returning (row_count, elapsed_ms). Honest timing."""
    thunk = f"{{[] st:.z.p; res:({q}); (count res;`long$(.z.p-st)%1000000)}}[]"
    out = q_eval(HDB_PORT, thunk, timeout=300)
    nums = re.findall(r"-?\d+", out)
    return (-1, -1) if out.startswith("ERR") or len(nums) < 2 else (int(nums[0]), int(nums[1]))


def qscalar(expr: str) -> str:
    return q_eval(HDB_PORT, expr, timeout=300).strip()


def transforms(compiled: str) -> list:
    """The bounds/filters the gate added under the hood, for display."""
    notes = []
    m = re.search(r"date within \S+ \S+|date=\d{4}\.\d{2}\.\d{2}", compiled)
    if m:
        notes.append(["partition bound", m.group(0),
                      "restricts the scan to named date partitions, never the whole DB"])
    if ENT_PRED in compiled:
        notes.append(["entitlement filter", ENT_PRED,
                      f"mandatory row filter for '{PRINCIPAL}', injected by the gate; "
                      "the agent cannot set, remove, or widen it"])
    m = re.search(r"i<(\d+)", compiled)
    if m:
        notes.append(["materialisation cap", f"i<{m.group(1)}",
                      "bounds rows read off disk per partition (raw listings only)"])
    m = re.search(r"(\d+) sublist", compiled)
    if m:
        notes.append(["result cap", f"{m.group(1)} sublist", "bounds the rows returned to the agent"])
    return notes


# ============================================================================
# 1. STRUCTURED QUERY — compiled + executed live through the gate
# ============================================================================
SHOULD_WORK = {
    "filter": {"title": "Filtered raw select (price>100), one partition",
        "req": {"table": "trade", "columns": ["sym", "time", "price", "size"],
                "filters": [{"col": "price", "op": ">", "value": 100}], "date": {"from": D0, "to": D0}},
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
    "asof": {"title": "As-of join trade |> quote, effective spread (heavy, honest)",
        "req": {"join": {"type": "asof", "on": ["sym", "time"],
                "left": {"table": "trade", "columns": ["sym", "time", "price"], "date": {"from": D0, "to": D0}},
                "right": {"table": "quote", "columns": ["sym", "time", "bid", "ask"], "date": {"from": D0, "to": D0}},
                "select": [{"as": "sym", "expr": {"col": "sym"}},
                           {"as": "eff_spread", "expr": {"op": "sub", "args": [{"col": "price"},
                            {"op": "div", "args": [{"op": "add", "args": [{"col": "bid"}, {"col": "ask"}]}, {"lit": 2}]}]}}]}},
        "proof": "asof"},
}


def do_structured(key: str) -> dict:
    c = SHOULD_WORK[key]
    compiled = GATE.safe_q(STRUCTURED_TOOL, {"request": c["req"]}, principal=PRINCIPAL)
    rows, ms = run_timed(compiled)
    out = {"title": c["title"], "request": c["req"], "compiled": compiled,
           "transforms": transforms(compiled), "rows": rows, "ms": ms, "tool": STRUCTURED_TOOL}
    if c["proof"] == "raw":
        syms = qscalar(f"`s#asc distinct exec sym from ({compiled})")
        out["proof"] = f"distinct sym in result = {syms} (subset of entitled {{AAPL,MSFT}})"
        out["note"] = ("a raw listing is a bounded sample: the i<1000000 cap takes the first 1M rows "
                       "by storage order. This partition is sym-sorted, so MSFT can sit beyond the cap; "
                       "the aggregations get no index cap and see both syms.")
    elif c["proof"] == "topn":
        syms = qscalar(f"`s#asc distinct exec sym from ({compiled})")
        out["proof"] = f"returned exactly {rows} rows (limit honoured); syms = {syms}"
    elif c["proof"] == "asof":
        syms = qscalar(f"`s#asc distinct exec sym from ({compiled})")
        out["proof"] = f"joined result syms = {syms} (both sides entitlement-filtered)"
        out["note"] = "the aj over the entitled trade x quote rows is genuinely heavy; the elapsed time is the real cost, shown honestly."
    elif c["proof"] == "ref":
        out["proof"] = f"matches an INDEPENDENT uncapped reference query: {q_match(HDB_PORT, compiled, c['ref'])}"
        out["ref"] = c["ref"]
    out["pass"] = rows >= 0
    _audit(STRUCTURED_TOOL, {"request": c["req"]}, Effect.ALLOW, None, None)
    return out


# ============================================================================
# 2. ROW-LEVEL ENTITLEMENTS — out-of-scope -> 0 rows; both filters in the q
# ============================================================================
def do_entitlement() -> dict:
    req = {"table": "trade", "columns": ["sym", "price"], "date": {"from": D0, "to": D0},
           "filters": [{"col": "sym", "op": "in", "value": ["GOOG", "NVDA"]}]}
    compiled = GATE.safe_q(STRUCTURED_TOOL, {"request": req}, principal=PRINCIPAL)
    rows, ms = run_timed(compiled)
    present = qscalar(f"`AAPL`GOOG`NVDA in exec sym from select distinct sym from trade where date={D0}")
    _audit(STRUCTURED_TOOL, {"request": req}, Effect.ALLOW, "entitlement.injected",
           "mandatory row filter ANDed into the request")
    return {"request": req, "compiled": compiled, "rows": rows, "ms": ms, "present": present,
            "pass": rows == 0}


# ============================================================================
# 3. FREE-FORM q — allowlist-on-parse: lift + RECOMPILE through the compiler
# ============================================================================
# Liftable / normalising cases — show the raw q AND the recompiled q.
FREEFORM_OK = {
    "plain": {"title": "Hand-written filtered select",
        "q": f"select sym,price,size from trade where price>100, date={D0}",
        "note": "lifted to a structured request, then recompiled — the recompiled q carries the entitlement and the cap. The raw q is never executed."},
    "normalise": {"title": "Date written SECOND — normalised to date-first (no full-partition scan)",
        "q": f"select sym,price from trade where size>500, date={D0}",
        "note": "the analyst put the date predicate second (a classic OOM foot-gun in kdb+). The compiler always emits date FIRST so the partition is pruned before any column is read — watch RSS stay flat."},
    "agg": {"title": "Hand-written aggregation (avg/sum by sym)",
        "q": f"select avg_px:avg price, tot:sum size by sym from trade where date={D0}",
        "note": "by-clause and allowlisted aggregations are in the safe subset; recompiled identically to the structured route."},
}

# Rejected cases — each names WHICH layer caught it.
#   LIFTER   : not in the safe subset -> FreeformRejected (no structured request ever formed)
#   COMPILER : lifts to a request, but fails the trusted compiler's allowlists
FREEFORM_BAD = {
    "system":  {"title": "system \"id\" — shell out", "q": "system \"id\""},
    "value":   {"title": "value \"delete trade\" — eval a string", "q": "value \"delete trade\""},
    "delete":  {"title": "delete from trade — mutation", "q": f"delete from trade where date={D0}"},
    "update":  {"title": "update price:0 from trade — mutation", "q": f"update price:0 from trade where date={D0}"},
    "twostmt": {"title": "two statements (select; delete)", "q": f"select sym from trade where date={D0}; delete from trade"},
    "subquery":{"title": "subquery in the from clause", "q": f"select sym from (select sym from trade where date={D0})"},
    "dotz":    {"title": ".z.P — touch the q namespace", "q": f"select .z.P from trade where date={D0}"},
    "hopen":   {"title": "hopen `:host:port — open a handle", "q": "select hopen from trade"},
    "badcol":  {"title": "off-allowlist COLUMN (trade.secret)", "q": f"select sym,secret from trade where date={D0}"},
    "badtable":{"title": "off-allowlist TABLE (positions)", "q": f"select sym from positions where date={D0}"},
    "nodate":  {"title": "missing date on a partitioned table", "q": "select sym,price from trade"},
}


def do_freeform_ok(key: str) -> dict:
    c = FREEFORM_OK[key]
    lifted = lift(c["q"])                       # the structured request the lifter produced
    recompiled = GATE.safe_q(FREEFORM_TOOL, {"query": c["q"]}, principal=PRINCIPAL)
    rows, ms = run_timed(recompiled)
    _audit(FREEFORM_TOOL, {"query": c["q"]}, Effect.ALLOW, "freeform.lifted_recompiled",
           "raw q lifted to the safe subset and recompiled through the trusted compiler")
    return {"title": c["title"], "raw": c["q"], "lifted": lifted, "recompiled": recompiled,
            "transforms": transforms(recompiled), "rows": rows, "ms": ms,
            "advisories": advisories(c["q"]), "note": c["note"], "pass": rows >= 0}


def do_freeform_bad(key: str) -> dict:
    c = FREEFORM_BAD[key]
    # Determine WHICH layer rejects: try the lifter first (the recogniser), then
    # the compiler (the boundary). The raw q is never executed either way.
    try:
        lift(c["q"])
        lifted_ok = True
    except FreeformRejected as e:
        _audit(FREEFORM_TOOL, {"query": c["q"]}, Effect.BLOCK, "freeform.lifter_reject", str(e))
        return {"title": c["title"], "raw": c["q"], "layer": "LIFTER",
                "reason": str(e), "blocked": True,
                "explain": "not in the safe subset — no structured request was ever formed, so nothing reached the compiler or kdb+."}
    # lifted, so the boundary is the compiler
    try:
        leaked = GATE.safe_q(FREEFORM_TOOL, {"query": c["q"]}, principal=PRINCIPAL)
        _audit(FREEFORM_TOOL, {"query": c["q"]}, Effect.ALLOW, "freeform.LEAKED", "should not happen")
        return {"title": c["title"], "raw": c["q"], "layer": "NONE", "blocked": False, "leaked": leaked}
    except StructuredQueryRejected as e:
        _audit(FREEFORM_TOOL, {"query": c["q"]}, Effect.BLOCK, "freeform.compiler_reject", str(e))
        return {"title": c["title"], "raw": c["q"], "layer": "COMPILER",
                "reason": str(e), "blocked": True, "lifted_ok": lifted_ok,
                "explain": "syntactically in the safe subset, so it lifted — but the trusted compiler re-validated table/column/date against the allowlist and refused. Defence in depth: the boundary fires a second time."}


# ============================================================================
# 4. SAFETY + RESOURCE — dangerous ops inexpressible; unbounded scan capped
# ============================================================================
def do_safety_inexpressible(key: str) -> dict:
    """A mutation/dangerous op cannot even be expressed: the structured schema has
    no delete/update verb, and free-form is rejected by the lifter."""
    qmap = {"delete": f"delete from trade where date={D0}",
            "update": f"update price:0 from trade where date={D0}"}
    qtext = qmap[key]
    try:
        lift(qtext)
        return {"q": qtext, "blocked": False}
    except FreeformRejected as e:
        _audit(FREEFORM_TOOL, {"query": qtext}, Effect.BLOCK, "safety.inexpressible", str(e))
        return {"q": qtext, "blocked": True, "layer": "LIFTER", "reason": str(e),
                "explain": "the structured grammar has no delete/update verb at all, and the free-form lifter rejects it — the operation is inexpressible, not merely denied."}


# Structured-route rejections folded in from the retired should/shouldnt demo:
# the compiler sanitises injected values/identifiers, enforces the span cap, and
# default-denies an un-entitled principal — proving unsafe input can't ride in
# through the structured route either.
STRUCTURED_REJECT = {
    "injval": {"title": "q-injection in a filter VALUE (AAPL`;system\"id\")", "step": "value sanitisation",
        "req": {"table": "trade", "columns": ["sym"], "date": {"from": D0, "to": D0},
                "filters": [{"col": "sym", "op": "=", "value": "AAPL`;system\"id\""}]}, "p": PRINCIPAL},
    "injcol": {"title": "q-injection in a COLUMN name (sym; delete trade)", "step": "identifier sanitisation",
        "req": {"table": "trade", "columns": ["sym; delete trade"], "date": {"from": D0, "to": D0}}, "p": PRINCIPAL},
    "span": {"title": "Raw range over the span cap (20 days > max 5)", "step": "span cap",
        "req": {"table": "trade", "columns": ["sym", "price"], "date": {"from": DATES[0], "to": DATES[19]}}, "p": PRINCIPAL},
    "meta": {"title": "meta by an UN-entitled principal (analyst-nobody)", "step": "entitlement gate (default-deny)",
        "req": {"table": "trade", "op": "meta"}, "p": "analyst-nobody"},
}


def do_structured_reject(key: str) -> dict:
    c = STRUCTURED_REJECT[key]
    try:
        leaked = GATE.safe_q(STRUCTURED_TOOL, {"request": c["req"]}, principal=c["p"])
        _audit(STRUCTURED_TOOL, {"request": c["req"]}, Effect.ALLOW, "structured.LEAKED", "should not happen", c["p"])
        return {"title": c["title"], "request": c["req"], "principal": c["p"], "step": c["step"],
                "blocked": False, "leaked": leaked}
    except StructuredQueryRejected as e:
        _audit(STRUCTURED_TOOL, {"request": c["req"]}, Effect.BLOCK, "structured.reject", str(e), c["p"])
        return {"title": c["title"], "request": c["req"], "principal": c["p"], "step": c["step"],
                "blocked": True, "reason": str(e)}


def do_safety_cap() -> dict:
    """A would-be unbounded scan, bounded by the materialisation cap."""
    raw = f"select from trade where date={D0}"          # no row filter, all columns
    recompiled = GATE.safe_q(FREEFORM_TOOL, {"query": raw}, principal=PRINCIPAL)
    rows, ms = run_timed(recompiled)
    partition_total = int(re.findall(r"-?\d+", qscalar(f"count select from trade where date={D0}"))[0])
    _audit(FREEFORM_TOOL, {"query": raw}, Effect.ALLOW, "resource.capped",
           f"materialisation bounded to i<{CAP}")
    return {"raw": raw, "recompiled": recompiled, "transforms": transforms(recompiled),
            "rows": rows, "ms": ms, "cap": CAP, "partition_total": partition_total,
            "pass": rows <= CAP,
            "explain": (f"Without the gate, `{raw}` would materialise the whole partition "
                        f"(~{partition_total:,} rows) for the agent — an OOM / DoS vector. The gate "
                        f"injects i<{CAP:,} and the entitlement, returning {rows:,} rows. The scan "
                        "is bounded by construction; it cannot blow up the box.")}


# ============================================================================
# 5. INJECTION DEFENCE (IFC) — untrusted-derived action blocked at the sink
# ============================================================================
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


def do_ifc(key: str) -> dict:
    c = IFC_CASES[key]
    prov = ifc.Provenance(_SINK)
    for it, lab in c["labels"].items():
        prov.observe(it, ifc.TRUSTED_PUBLIC if lab == "T" else ifc.UNTRUSTED_PUBLIC)
    finding = prov.guard("submit_order", c["items"])
    joined = prov.label_of(c["items"])
    got = "ALLOW" if finding is None else "BLOCK"
    _audit("submit_order", {"derived_from": c["items"]},
           Effect.ALLOW if finding is None else Effect.BLOCK,
           finding.rule_id if finding else None, finding.reason if finding else None)
    return {"title": c["title"], "items": c["items"], "expect": c["expect"], "verdict": got,
            "integrity": "TRUSTED" if joined.trusted else "UNTRUSTED",
            "rule": finding.rule_id if finding else None,
            "reason": finding.reason if finding else None,
            "pass": (c["expect"] == "ALLOW") == (finding is None)}


# ============================================================================
# 6. THE RECORD — signed policy (fail-closed) + WORM hash-chained audit
# ============================================================================
def do_record() -> dict:
    valid, reason = signing.verify(_POLICY_BYTES, _SIG, _PUB, _ALGO)
    # honest tamper demo: flip one byte of the signed policy -> signature fails
    tampered = bytearray(_POLICY_BYTES)
    tampered[tampered.index(b"max_rows")] = ord("M")           # 'max_rows' -> 'Max_rows'
    t_valid, t_reason = signing.verify(bytes(tampered), _SIG, _PUB, _ALGO)
    chain_ok, n, err = AUDIT.verify()
    anchor_ok, anchor_msg = AUDIT.verify_against_anchor()
    tail = []
    if AUDIT.path.exists():
        lines = [ln for ln in AUDIT.path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        for ln in lines[-8:]:
            e = json.loads(ln)
            tail.append({"seq": e["seq"], "ts": e["ts"], "principal": e["principal"],
                         "tool": e["tool"], "effect": e["effect"],
                         "rules": e.get("rules", []), "entry_hash": e["entry_hash"][:16]})
    return {
        "policy": {"path": str(POLICY.relative_to(REPO)), "algo": _ALGO, "key_id": _SIG["key_id"],
                   "sha256": _SIG["sha256"][:16] + "…", "valid": valid, "reason": reason,
                   "tamper_valid": t_valid, "tamper_reason": t_reason},
        "audit": {"entries": n, "chain_ok": chain_ok, "chain_err": err,
                  "anchor_ok": anchor_ok, "anchor_msg": anchor_msg, "tail": tail},
        "confinement": ("the gate runs out-of-process behind OS confinement (seccomp syscall "
                        "deny-list + read-only policy mount). The agent's only wire out is the "
                        "gate's decision API — it cannot reach kdb+, the policy, or the audit log directly."),
    }


# ============================================================================
# HTTP plumbing
# ============================================================================
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
        routes = {
            "/api/structured": lambda: do_structured(req["case"]),
            "/api/entitlement": do_entitlement,
            "/api/freeform_ok": lambda: do_freeform_ok(req["case"]),
            "/api/freeform_bad": lambda: do_freeform_bad(req["case"]),
            "/api/safety_inexpressible": lambda: do_safety_inexpressible(req["case"]),
            "/api/structured_reject": lambda: do_structured_reject(req["case"]),
            "/api/safety_cap": do_safety_cap,
            "/api/ifc": lambda: do_ifc(req["case"]),
            "/api/record": do_record,
        }
        fn = routes.get(self.path)
        if not fn:
            return self._send(404, json.dumps({"error": "no such endpoint"}))
        try:
            self._send(200, json.dumps(fn()))
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
    print(f"[aegis-demo] HDB up ({len(DATES)} partitions, {D0}..{DATES[-1]}). "
          f"policy signed ({_ALGO}, key_id={_SIG['key_id']}).")
    print(f"[aegis-demo] LIVE on http://localhost:{PORT}/  — one page, six capabilities, real data.")
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
