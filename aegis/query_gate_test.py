"""Prove the single query chokepoint: structured + free-form both return safe,
bounded, entitled q from the trusted compiler; free-form outside the safe subset
is rejected; the free-form route can be turned off entirely.

Run:  python -m aegis.query_gate_test
"""

from __future__ import annotations

import sys

from .freeform_q import FreeformRejected
from .query_compiler import QueryCompiler, StructuredQueryRejected
from .query_gate import QueryGate

POLICY = {
    "allowed_tables": ["trade", "quote"],
    "require_date_tables": ["trade", "quote"],
    "max_rows": 1_000_000,
    "columns": {"trade": ["date", "time", "sym", "price", "size", "region"],
                "quote": ["date", "time", "sym", "bid", "ask", "region"]},
    "entitlements": {"mode": "default_deny", "principals": {
        "analyst": {"row_filters": {"*": [{"col": "region", "op": "in", "value": ["EMEA"]}]}}}},
}
QC = QueryCompiler(POLICY)
P = "analyst"


def run() -> int:
    fails = 0

    def chk(name, cond, detail=""):
        nonlocal fails
        print(f"  {'ok ' if cond else 'XX '} {name}")
        if not cond:
            fails += 1
            if detail != "":
                print(f"        {detail}")

    gate = QueryGate(QC)

    # structured route
    out = gate.safe_q("run_structured_query",
                      {"request": {"table": "trade", "columns": ["sym", "price"],
                                   "date": {"from": "2025.06.01", "to": "2025.06.01"}}}, P)
    chk("structured tool -> bounded, entitled q", "region in `EMEA" in out and "sublist" in out, out)

    # free-form route: lifted + recompiled, carries the entitlement
    out = gate.safe_q("run_query", {"query": "select sym, price from trade where date=2025.06.01"}, P)
    chk("free-form tool -> lifted + recompiled to entitled q", "region in `EMEA" in out, out)

    # free-form normalisation: date-second -> date-first
    out = gate.safe_q("run_query", {"query": "select sym from trade where size>500, date=2025.06.01"}, P)
    chk("free-form date-second normalised to date-first", 0 <= out.find("date") < out.find("size"), out)

    # free-form outside the safe subset -> rejected
    blocked = False
    try:
        gate.safe_q("run_query", {"query": 'system "rm -rf /"'}, P)
    except (FreeformRejected, StructuredQueryRejected):
        blocked = True
    chk("free-form `system ...` rejected", blocked)

    # free-form lifted but off-allowlist -> rejected by the compiler (second gate)
    blocked = False
    try:
        gate.safe_q("run_query", {"query": "select sym from trade"}, P)  # no date
    except StructuredQueryRejected:
        blocked = True
    chk("free-form with no date -> rejected by the compiler", blocked)

    # missing query string
    blocked = False
    try:
        gate.safe_q("run_query", {}, P)
    except StructuredQueryRejected:
        blocked = True
    chk("free-form tool with no query string -> rejected", blocked)

    # structured-only deployment: free-form route OFF
    locked = QueryGate(QC, allow_freeform=False)
    blocked = False
    try:
        locked.safe_q("run_query", {"query": "select sym from trade where date=2025.06.01"}, P)
    except StructuredQueryRejected as e:
        blocked = "disabled" in str(e)
    chk("allow_freeform=False disables the free-form route entirely", blocked)
    # ...while structured still works
    out = locked.safe_q("run_structured_query",
                        {"request": {"table": "trade", "columns": ["sym"],
                                     "date": {"from": "2025.06.01", "to": "2025.06.01"}}}, P)
    chk("structured route still works when free-form is off", "region in `EMEA" in out, out)

    # unknown / non-query tool
    blocked = False
    try:
        gate.safe_q("send_email", {"to": "x"}, P)
    except StructuredQueryRejected:
        blocked = True
    chk("non-query tool -> rejected (not a query surface)", blocked)

    print(f"\n{'PASS' if fails == 0 else 'FAIL'} - {fails} failure(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(run())
