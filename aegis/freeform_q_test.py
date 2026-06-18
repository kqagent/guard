"""Prove the free-form q governance: allowlist-on-parse + lift + recompile.

Good free-form q in the safe subset is lifted and RECOMPILED through the trusted
compiler (so it comes back bounded, date-first, entitlement-injected). Everything
outside the safe subset is REJECTED - either by the lifter (not the safe grammar)
or by the compiler (lifted, but off the allowlists). The agent's raw q is never run.

Pure / stdlib-only.  Run:  python -m aegis.freeform_q_test
"""

from __future__ import annotations

import sys

from .freeform_q import FreeformRejected, advisories, compile_freeform, lift
from .query_compiler import QueryCompiler, StructuredQueryRejected

POLICY = {
    "allowed_tables": ["trade", "quote"],
    "require_date_tables": ["trade", "quote"],
    "max_rows": 1_000_000,
    "columns": {
        "trade": ["date", "time", "sym", "price", "size", "region"],
        "quote": ["date", "time", "sym", "bid", "ask", "region"],
    },
    "entitlements": {"mode": "default_deny", "principals": {
        "analyst": {"row_filters": {"*": [{"col": "region", "op": "in", "value": ["EMEA"]}]}},
    }},
}
QC = QueryCompiler(POLICY)
P = "analyst"

# Each ACCEPT case lifts AND recompiles to safe q. We assert the recompiled output
# carries the by-construction safety (entitlement + cap), proving we run the
# COMPILER's q, not the agent's text.
ACCEPT = [
    "select sym, price from trade where date=2025.06.01",
    "select sym, price, size from trade where date=2025.06.01, sym in `AAPL`MSFT, size>500",
    "select avg price by sym from trade where date=2025.06.01",
    "select avg_px:avg price, tot:sum size by sym from trade where date=2025.06.01",
    "select size wavg price by sym from trade where date=2025.06.01",
    "select count i by sym from trade where date=2025.06.01",
    "select countdistinct sym from trade where date=2025.06.01",  # single-token countdistinct lifts
    # data-quality idiom: count nulls per symbol (`sum null bid`) — the agent's
    # real diagnostic query, lifted via the allowlisted `null` agg modifier.
    "select count i, nb:sum null bid, na:sum null ask by sym from quote where date=2025.06.01",
    "select sym from trade where date within 2025.06.01 2025.06.03",
    # recent-window "is it still happening?" diagnostic: the compiler emits .z.p
    # itself and re-validates the timespan; only the bounded span comes from text.
    "select sym, price from trade where date=2025.06.01, time > .z.p - 0D00:05",
    "select sym, price from trade where date=2025.06.01, time within (.z.p - 0D01:00; .z.p)",
    "meta trade",
    "select sym, price from trade where sym in (`AAPL;`MSFT), date=2025.06.01",  # ';' inside list is fine
]

# REJECTED BY THE LIFTER - not in the safe subset at all.
REJECT_LIFT = [
    'system "rm -rf /"',
    'value "select sym from trade"',
    "delete from trade where date=2025.06.01",
    "update price:0 from trade where date=2025.06.01",
    'select sym from trade where date=2025.06.01; system "id"',   # two statements
    "select {x} from trade where date=2025.06.01",                # brace -> reject
    "select .z.P from trade where date=2025.06.01",               # '.' -> reject
    "select sym from trade where price > (select max price from quote)",  # subquery value
    'select sum null (system "id") by sym from trade where date=2025.06.01',  # null-modifier can't smuggle a call
    "select sum evil bid by sym from trade where date=2025.06.01",            # unknown modifier word
    'select sym from trade where date=2025.06.01, time > .z.p - (system "id")',  # now-arith can't smuggle a call
    "select sym from trade where date=2025.06.01, time > .z.exit - 0D00:05",   # only pure now-reads allowed
    "select .z.p from trade where date=2025.06.01",                            # bare .z.p as a column -> reject
    "select sym from trade where date=2025.06.01, time > .z.p - 0D00:05*99",   # extra arithmetic -> reject
    "select sym from trade where date=2025.06.01 exit 0",         # trailing junk
    'hopen `:prod:5010',
    "exec sym from trade where date=2025.06.01",                  # exec changes result shape -> rejected
]

# LIFTS, but the COMPILER rejects it (off the allowlists / missing bound) - the
# second gate. Still blocked; the agent's text never runs.
REJECT_COMPILE = [
    "select sym from trade",                                 # partitioned, no date
    "select sym, secret from trade where date=2025.06.01",   # column not on allowlist
    "select sym from positions where date=2025.06.01",       # table not on allowlist
    # recent-window magnitude cap: a huge `.z.p - <days>D` span would match all
    # history (defeating the bound) -> rejected by the compiler.
    "select sym from trade where date=2025.06.01, time > .z.p - 9999999D00:00",
]


def run() -> int:
    fails = 0

    def chk(name, cond, detail=""):
        nonlocal fails
        print(f"  {'ok ' if cond else 'XX '} {name}")
        if not cond:
            fails += 1
            if detail != "":
                print(f"        {detail}")

    print("ACCEPT (lifted + recompiled to safe, bounded, entitled q):")
    for q in ACCEPT:
        try:
            out = compile_freeform(q, QC, principal=P)
            # meta is the one form with no rows/cap; everything else must carry the
            # mandatory entitlement, proving it is the COMPILER's output.
            ok = "meta " in out or ("region in `EMEA" in out)
            chk(q, ok, out)
        except (FreeformRejected, StructuredQueryRejected) as e:
            chk(q, False, f"unexpectedly rejected: {e}")

    print("\nREJECTED BY THE LIFTER (not the safe subset):")
    for q in REJECT_LIFT:
        try:
            compile_freeform(q, QC, principal=P)
            chk(q, False, "was NOT rejected")
        except FreeformRejected:
            chk(q, True)
        except StructuredQueryRejected as e:
            chk(q, True, f"(rejected by compiler instead, also fine: {e})")

    print("\nLIFTS but COMPILER rejects (second gate; still blocked):")
    for q in REJECT_COMPILE:
        try:
            compile_freeform(q, QC, principal=P)
            chk(q, False, "was NOT rejected")
        except StructuredQueryRejected:
            chk(q, True)
        except FreeformRejected as e:
            chk(q, True, f"(lifter rejected it, also fine: {e})")

    # The headline property: a date-SECOND query is NORMALISED to date-first by
    # recompilation - the OOM foot-gun is fixed, not just flagged.
    print("\nnormalisation + advisory:")
    out = compile_freeform("select sym, price from trade where size>500, date=2025.06.01", QC, principal=P)
    di, si = out.find("date"), out.find("size")
    chk("date-second free-form q recompiles to date-FIRST q", 0 <= di < si, out)
    chk("advisory flags the original as a non-date-first foot-gun",
        any("date-first" in a or "full-partition" in a for a in
            advisories("select sym from trade where size>500, date=2025.06.01")))

    # lift() shape spot-check
    req = lift("select avg_px:avg price by sym from trade where date=2025.06.01, sym in `AAPL`MSFT")
    chk("lift produces a structured request (table/by/aggs/filters/date)",
        req.get("table") == "trade" and req.get("by") == ["sym"]
        and req["aggs"][0]["fn"] == "avg" and req["date"]["from"] == "2025.06.01"
        and req["filters"][0]["value"] == ["AAPL", "MSFT"], req)

    print(f"\n{'PASS' if fails == 0 else 'FAIL'} - {fails} failure(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(run())
