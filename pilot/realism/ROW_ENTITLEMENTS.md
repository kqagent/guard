# Row-level entitlements — mandatory predicate injection (the row plane)

Aegis already controls which **tables / columns / shapes** an agent may query. This
adds control over which **rows** — the Satori/Immuta row-level-security model, done
at the q query plane by the compiler. A per-principal row filter is **mandatorily
injected** into every compiled query: non-removable, ANDed with the agent's own
filters and the date filter. The agent cannot opt out and cannot widen past its set.

## Policy

A top-level `entitlements` block (merged into the compiler config by `from_policy`):

```json
"entitlements": {
  "mode": "default_deny",
  "principals": {
    "analyst-equities": {"row_filters": {"trade": [{"col":"sym","op":"in","value":["AAPL","MSFT"]}],
                                          "quote": [{"col":"sym","op":"in","value":["AAPL","MSFT"]}]}},
    "analyst-emea":     {"row_filters": {"*": [{"col":"region","op":"in","value":["EMEA"]}]}}
  }
}
```

- `mode: "default_deny"` (recommended) — a principal with no entitlement for a queried
  table is **rejected** (sees nothing). `mode: "open"` (default when absent) — no row
  filter for non-entitled deployments (backward-compatible; existing behaviour).
- Per-table key, or `"*"` wildcard. Filters reuse the exact structured-filter grammar.

## Why it cannot be escaped

- **Single chokepoint.** The predicate is injected in `_where_expr`, through which
  *every* table reference flows — top-level selects **and both sides of every
  join/setop** (each side is compiled via `_compile_select`). A computed-column /
  compute-over-join `select` runs over the already-filtered inputs.
- **Mandatory + ANDed.** It is appended to the `where` clause regardless of request
  content, so it ANDs with the agent's own predicates. If the agent also asks for a
  non-entitled symbol, the result is the **intersection** (empty), not a widening.
- **Principal from the PDP.** `compile(request, principal=…)` takes the principal as
  an argument from the authenticated action — **never from the request body** (a
  `principal` key in the request is ignored).
- **Injection-safe.** Entitlement columns go through the column allowlist (`_col`) and
  values through the scalar path (`_scalar`) — an entitlement value can no more inject
  q than a user value can.

## Proven (unit + real 4B estate)

`aegis/query_compiler_entitlements_test.py` (in `run_all_checks`, 28/28) — 14 cases:
mandatory-AND, can't-escape intersection, joins+setops both-sided, default-deny reject,
wrong-table reject, `*` wildcard, hostile value/column reject, open-mode no-op,
request-body principal ignored, plus the span cap.

On the real 500M-row HDB (`analyst-equities` entitled to AAPL/MSFT):
- distinct symbols the analyst can see: **`AAPL`MSFT only**.
- explicit request for GOOG/NVDA: **0 rows** (intersection with the entitlement).
- entitled `count`: 392,793 vs 10,000,000 full partition (filter applies at scale).
- **left-join** trade⋈quote by sym: result keys **`AAPL`MSFT only** — a join cannot
  surface a non-entitled row.

## Raw-select date-range cap (same slice)

`query_proxy.max_partition_span` (days). A **raw row-listing** whose date range exceeds
it is rejected — bounding global materialisation (a raw listing reads up to `max_rows`
*per partition*). **Reducing queries** (aggs/by/distinct) are exempt: they must read
their input and their result is already result-capped. Proven: a 50-day raw listing is
rejected; a 5-day one returns ≤ `max_rows` rows.
