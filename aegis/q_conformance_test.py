"""q-semantics conformance battery — prove the compiler's safety bounds hold on
REAL kdb+, not just in Python unit tests.

The query compiler is the primary control. Its guarantees rest on assumptions
about how q *evaluates* the emitted query:
  * `..., i<N`  bounds the rows a RAW listing materialises off disk;
  * a reducing query (count/sum/avg/by/distinct) must NOT carry `i<N` or its
    answer is corrupted (count would return the cap, not the truth);
  * `N sublist (...)` caps the RESULT without corrupting an aggregation;
  * a mandatory entitlement predicate, ANDed into WHERE, actually filters rows
    (and a contradictory agent filter intersects to empty — cannot widen);
  * the emitted q is read-only — it never mutates the database.

"We believe q does X" is weaker than "here is a test that fails if q ever
doesn't." This battery compiles representative + adversarial requests with the
REAL `QueryCompiler`, runs each emitted query against a real partitioned HDB,
and asserts the property in q's runtime.

OPTIONAL tier: needs a q binary. If none is found it SKIPS cleanly (exit 0) so
the core suite is unaffected on machines without kdb+. On a box WITH q (a dev
laptop via WSL, or a prod Linux box) a genuine q-semantics violation makes it
exit non-zero.

Config (env, all optional):
    AEGIS_Q_BIN   path to the q binary   (default: $HOME/kdbx/l64/q)
    AEGIS_QHOME   QHOME                   (default: $HOME/kdbx)
    AEGIS_QLIC    QLIC dir (kc.lic)       (default: $HOME/kdbx)
On Windows the q command is auto-wrapped in `wsl` (q runs in WSL).

Run:  python -m aegis.q_conformance_test
"""

from __future__ import annotations

import sys

from .qexec import q_available, q_run, run_bash
from .query_compiler import QueryCompiler, StructuredQueryRejected

# -- q invocation ----------------------------------------------------------

WORK = "/tmp/aegis_qconf"
HDB = f"{WORK}/hdb"
N = 5000                       # rows per partition per table
DATES = ["2025.06.02", "2025.06.03", "2025.06.04"]
CAP = 1000                     # small max_rows so the materialisation cap is observable


# -- HDB fixture -----------------------------------------------------------

def build_hdb() -> str:
    """Build a tiny 3-partition trade/quote HDB. Small by design: the safety
    PROPERTIES (cap holds, aggregate not corrupted, entitlement filters) are
    scale-independent, so N=5000 with CAP=1000 makes every bound observable
    without generating hundreds of millions of rows."""
    dts = " ".join(DATES)
    prog = f"""
system "rm -rf {HDB}"; system "mkdir -p {HDB}";
system "S 42";
syms:`AAPL`MSFT`VOD`HSBC`BP;
regs:`EMEA`AMER`APAC;
n:{N};
mk:{{[d]
  trade::([] time:asc n?0D06:00:00.000000000; sym:n?syms; region:n?regs; price:100f+n?50f; size:100*1+n?100j);
  quote::([] time:asc n?0D06:00:00.000000000; sym:n?syms; region:n?regs; bid:100f+n?50f; ask:100f+n?50f);
  .Q.dpft[hsym `$"{HDB}"; d; `sym; `trade];
  .Q.dpft[hsym `$"{HDB}"; d; `sym; `quote]; }};
mk each {dts};
-1 "BUILT";
exit 0;
"""
    out = q_run(prog, workdir=WORK, timeout=180)
    return out


def _eval(expr_program: str, timeout: int = 120) -> str:
    """Load the HDB then run a q snippet that prints ONE token; return that token."""
    prog = f'system "l {HDB}";\n{expr_program}\nexit 0;'
    out = q_run(prog, workdir=WORK, timeout=timeout)
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return lines[-1] if lines else ""


def hdb_fingerprint() -> str:
    """A cheap content fingerprint of the HDB tree (paths + sizes), to prove no
    compiled query mutates anything on disk."""
    return run_bash(f"find {HDB} -type f -printf '%P %s\\n' 2>/dev/null | sort | md5sum")


# -- the battery -----------------------------------------------------------

# A principal entitled to ALL regions (so cap/aggregate tests aren't narrowed),
# plus an EMEA-only principal for the entitlement-effectiveness tests.
CFG = {
    "allowed_tables": ["trade", "quote"],
    "require_date_tables": ["trade", "quote"],
    "max_rows": CAP,
    "columns": {
        "trade": ["date", "time", "sym", "region", "price", "size"],
        "quote": ["date", "time", "sym", "region", "bid", "ask"],
    },
    "agg_fns": ["avg", "sum", "min", "max", "count", "first", "last", "wavg", "countdistinct"],
    "entitlements": {"mode": "default_deny", "principals": {
        "all": {"row_filters": {"*": [{"col": "region", "op": "in", "value": ["EMEA", "AMER", "APAC"]}]}},
        "emea": {"row_filters": {"*": [{"col": "region", "op": "in", "value": ["EMEA"]}]}},
    }},
}
D = DATES[0]


def run() -> int:
    if not q_available():
        print("SKIP — no q binary found (set AEGIS_Q_BIN). q-conformance needs real kdb+.")
        print("SKIP")
        return 0

    print(f"q found; building fixture HDB ({len(DATES)} partitions x {N} rows)...")
    b = build_hdb()
    if "BUILT" not in b:
        print("FAIL — could not build fixture HDB:\n" + b)
        return 2

    qc = QueryCompiler(CFG)
    fp_before = hdb_fingerprint()
    fails = 0
    compiled_seen: list[str] = []

    def check(name, cond, detail=""):
        nonlocal fails
        print(f"  {'ok ' if cond else 'XX '} {name}")
        if not cond:
            fails += 1
            if detail:
                print(f"        {detail}")

    def comp(req, principal):
        out = qc.compile(req, principal=principal)
        compiled_seen.append(out)
        return out

    # --- P1: RAW-listing materialisation cap holds in q ---------------------
    # 5000 rows match; emitted carries i<CAP; q must return exactly CAP rows.
    raw = comp({"table": "trade", "columns": ["sym", "price"], "date": {"from": D, "to": D}}, "all")
    check("P1 emitted raw select carries the `i<CAP` scan bound", f"i<{CAP}" in raw, raw)
    got = _eval(f"-1 .Q.s1 count ({raw});")
    check(f"P1 raw select returns exactly {CAP} rows on real q (cap holds, not {N})",
          got == str(CAP), f"q returned count={got!r}")

    # --- P2: REDUCING query is NOT corrupted by the cap ---------------------
    # The cap omission for reducers is the regression that bit us at 500M scale
    # (count returned 1e6 not 1e7). Prove count == truth N, NOT the cap.
    cnt = comp({"table": "trade", "aggs": [{"fn": "count", "as": "n"}], "date": {"from": D, "to": D}}, "all")
    check("P2 emitted count query has NO `i<` scan cap (would corrupt the count)", "i<" not in cnt, cnt)
    got = _eval(f"-1 .Q.s1 exec first n from ({cnt});")
    check(f"P2 count returns the TRUTH {N} on real q (cap did not corrupt it)",
          got == str(N), f"q returned n={got!r} (cap-corruption would show {CAP})")

    # --- P2b: aggregate VALUES match an independent uncapped ground truth ----
    agg = comp({"table": "trade",
                "aggs": [{"fn": "count", "as": "n"}, {"fn": "sum", "col": "size", "as": "s"},
                         {"fn": "avg", "col": "price", "as": "a"}],
                "date": {"from": D, "to": D}}, "all")
    truth = f"select n:count i, s:sum size, a:avg price from trade where date={D}"
    got = _eval(f"-1 .Q.s1 ({agg}) ~ ({truth});")
    check("P2b compiled count/sum/avg == independent uncapped ground truth", got == "1b", f"match={got!r}")

    # --- P2c: grouped (by) reducing query also uncorrupted ------------------
    grp = comp({"table": "trade", "by": ["sym"], "aggs": [{"fn": "count", "as": "n"}],
                "date": {"from": D, "to": D}}, "all")
    truth_g = f"select n:count i by sym from trade where date={D}"
    got = _eval(f"-1 .Q.s1 ({grp}) ~ ({truth_g});")
    check("P2c grouped `count by sym` == uncapped truth (per-group counts intact)",
          got == "1b", f"match={got!r}")
    got = _eval(f"-1 .Q.s1 (exec sum n from ({grp})) = {N};")
    check(f"P2c per-group counts sum back to {N} (no group truncated by a scan cap)",
          got == "1b", got)

    # --- P3: entitlement predicate actually filters rows in q ---------------
    ent = comp({"table": "trade", "columns": ["sym", "region", "price"], "date": {"from": D, "to": D}}, "emea")
    check("P3 emitted query for `emea` carries the region predicate", "region in `EMEA" in ent, ent)
    # `region` is an ENUMERATED symbol on disk (.Q.dpft enumerates against `sym),
    # so compare VALUES (`=`, which resolves the enumeration), not vector identity
    # (an enum-vs-plain `~` is false on type even when values match).
    got = _eval(f"reg: exec region from ({ent});\n-1 .Q.s1 (0 < count reg) and all reg = `EMEA;")
    check("P3 `emea` principal sees ONLY region=EMEA rows on real q (and rows are returned)",
          got == "1b", f"region-check={got!r}")

    # --- P3b: a contradictory agent filter intersects to empty (can't widen) -
    widen = comp({"table": "trade", "columns": ["sym", "region"], "date": {"from": D, "to": D},
                  "filters": [{"col": "region", "op": "in", "value": ["AMER"]}]}, "emea")
    got = _eval(f"-1 .Q.s1 count ({widen});")
    check("P3b emea + agent-filter AMER -> 0 rows (intersection, cannot widen past entitlement)",
          got == "0", f"q returned count={got!r}")

    # --- P4: date-partition pruning — only the asked partition's rows return -
    pruned = comp({"table": "trade", "columns": ["date", "sym"], "date": {"from": D, "to": D}}, "all")
    got = _eval(f"-1 .Q.s1 (distinct exec date from ({pruned})) ~ enlist {D};")
    check(f"P4 single-date query returns rows only from partition {D}", got == "1b", f"distinct-date match={got!r}")

    # --- P5: the compiler cannot EMIT a mutation / dangerous op -------------
    # The grammar has no slot for these; the backstop fails closed. Confirm at
    # the boundary that hostile request shapes raise rather than compile.
    hostile = [
        ({"table": "trade", "columns": ["sym; delete trade"], "date": {"from": D, "to": D}}, "bad column token"),
        ({"table": "trade", "columns": ["sym"], "date": {"from": D, "to": D},
          "filters": [{"col": "sym", "op": "=", "value": "AAPL`;system\"id\""}]}, "injection in value"),
        ({"table": "trade", "op": "drop"}, "unknown op (no mutation grammar)"),
    ]
    for req, why in hostile:
        rejected = False
        try:
            qc.compile(req, principal="all")
        except StructuredQueryRejected:
            rejected = True
        except Exception:
            rejected = True
        check(f"P5 hostile request rejected, never compiled ({why})", rejected)

    # --- P6: emitted queries left the database byte-identical (read-only) ----
    fp_after = hdb_fingerprint()
    check("P6 HDB on disk is byte-identical after the whole battery (no compiled query mutated it)",
          fp_before == fp_after and bool(fp_before), f"{fp_before!r} vs {fp_after!r}")
    # belt-and-braces: no emitted query string contains a mutation/dangerous token
    bad_tokens = ["delete ", "update ", "insert ", "upsert", "set ", "system", "hopen", "hdel", ".z.", "0:"]
    leaked = [t for s in compiled_seen for t in bad_tokens if t in s.lower()]
    check("P6 no emitted query contains a mutation/dangerous token", not leaked, f"leaked={leaked}")

    # --- P7: int-overflow on `sum` — documented q semantic (informational) ---
    # q `sum` over a 64-bit long column wraps silently. The compiler does NOT
    # currently widen sums; this is an honest known limitation (a sum over a huge
    # integer column could overflow). Shown, not gated — it is a correctness note,
    # not a security bound.
    wrap = _eval("-1 .Q.s1 (sum 2#0Wj) < 0;")   # 0Wj is max long; summing two wraps negative
    if wrap == "1b":
        print("  NOTE P7 q `sum` over int64 wraps silently (sum of two max-longs < 0). "
              "Compiler does not widen sums — known limitation, documented in "
              "docs/Aegis-System-Overview.md section 8.")

    print(f"\n{'PASS' if fails == 0 else 'FAIL'} — {fails} failure(s) against real kdb+")
    # cleanup
    run_bash(f"rm -rf {WORK}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(run())
