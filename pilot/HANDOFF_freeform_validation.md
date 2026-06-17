# Handoff: validate free-form q (allowlist-on-parse + recompile) on the real estate

**Branch:** `pilot/row-entitlements` (free-form governance at `2c43d93`)
**Why:** TorQ-ops is an API agent with no Claude Code hook and no kqagent, so Aegis
itself must quality-control the on-the-fly q the model writes. I built it
(`aegis/freeform_q.py` + `aegis/query_gate.py`, suite 34/34): free-form q is parsed,
the safe subset is lifted to a structured request, and **recompiled through the
trusted compiler** - the agent's raw q is never executed. I can't prove it *runs
correctly at scale* from this laptop; that's you.

## What's built
- `freeform_q.lift(qtext)` -> structured request (safe subset only; rejects the rest).
- `freeform_q.compile_freeform(qtext, compiler, principal)` -> lift + recompile to
  bounded, date-first, entitlement-injected q.
- `query_gate.QueryGate.safe_q(tool, input, principal)` -> the one chokepoint a tool
  executor calls: structured tool -> compiler; free-form tool -> compile_freeform;
  `allow_freeform=False` disables raw q entirely.

## Your job 1 - correctness on real kdb+
For a set of safe-subset free-form queries (select/exec/meta, where, by, aggs):
1. `compile_freeform(q)` -> execute the result on the live HDB.
2. Confirm it **equals an independent reference** - the same query you'd run directly,
   or via the structured tool. The recompiled output is what runs, not the agent's text,
   so prove the lift preserved intent (same rows/aggregates) on real data.
3. Confirm the recompiled q carries the **entitlement filter + cap** (same as structured).
4. **Normalisation:** feed a date-*second* query (`select ... where size>500, date=...`);
   confirm the recompiled q is date-*first*, returns the correct rows, and does NOT
   full-scan / OOM (watch RSS) - the foot-gun is fixed by recompilation.

## Your job 2 - rejection holds (nothing reaches kdb+)
Confirm these free-form inputs are rejected by the lifter and **no q executes**:
`system "..."`, `value "..."`, `delete`/`update`, two statements (`;`), a subquery
value, `.z.*`/braces, `hopen`. And off-allowlist (bad table/column, missing date) is
rejected by the compiler (second gate). Spot-check the *advisory* foot-gun notes too.

## Your job 3 - wire into the harness + re-soak
Wire `QueryGate` into the realism/live-agent free-form tool (`run_query` in
`aegis/live_kdb_agent.py` currently uses the older `QueryGuard` proxy - swap it for
`QueryGate.safe_q` so free-form goes through lift+recompile). Re-run the realism soak
with the free-form tool enabled and confirm: attack-success stays **0**, benign
served-and-correct is unchanged, and any genuinely-needed free-form diagnostic that the
safe subset can't express is cleanly **rejected** (it should go to break-glass, not run).

## Report back
The correctness comparison (recompiled == reference) on real data, the
normalisation/no-OOM result, the rejection set (all blocked, nothing ran), and the
re-soak numbers. Honest note: the recognised grammar is a curated subset - tell me which
real diagnostic queries it *couldn't* lift, so I can prioritise growing the grammar.
