# Structured query API — the query plane done right (design)

*2026-06-14. Proposed redesign of the kdb+/q query plane, prompted by the FSP
pilot. Status: design for review + homer implementation against the live estate.
Not yet built.*

## Why

Today the agent sends **free-form q text** and `QueryGuard` polices it with a
parser + a `_DANGEROUS_Q` deny-list. Every pilot review round found another q
escape hatch (`system`, then `.Q.en`/`reval`/`-11!`, …), and the only way to
accept legitimate idioms (`aj`, `wj`, `meta`) is to add more regex to the most
security-critical file — which adds hiding places for the next bypass. That is
**enumerate-badness on a Turing-complete language**: an arms race we lose slowly,
and it contradicts Aegis's own first principle (enumerate goodness, default-deny).

**Fix: the agent never sends q.** It sends a *structured request* (data, not
code); the proxy **compiles** it into safe, bounded q. There is no free-form q
to escape, so the injection surface and the coverage gap disappear together.

## The request (data, not code)

```json
{
  "table":   "trade",
  "columns": ["sym", "price", "size"],          // or aggregations (below)
  "date":    {"from": "2025.06.01", "to": "2025.06.13"},
  "filters": [                                    // structured, never q text
    {"col": "sym",  "op": "in",  "value": ["AAPL", "MSFT"]},
    {"col": "price","op": ">",   "value": 100}
  ],
  "by":      ["sym"],                             // optional grouping
  "aggs":    [{"fn": "avg", "col": "price", "as": "vwap_px"}],
  "limit":   100000
}
```

The proxy compiles that to, e.g.:
`select vwap_px:avg price by sym from trade where date within 2025.06.01 2025.06.13, sym in `AAPL`MSFT, price>100, i<100000`

## What makes it safe (enumerate goodness)

Every field is validated against an allowlist before compilation; anything not
on it is rejected, fail-closed:

- **table** ∈ `allowed_tables` (already in policy).
- **columns / by / agg cols** ∈ a per-table **column allowlist** (new) — so an
  agent can't reference an un-vetted column, and there is no place to inject.
- **filter ops** ∈ a fixed set (`=,<,>,<=,>=,in,within,like`); **values are
  typed literals**, escaped by the compiler, never interpolated as q.
- **aggs / fns** ∈ an **aggregation allowlist** (`avg,sum,min,max,count,first,
  last,wavg,…`) — named, vetted q functions only.
- **date** required for partitioned tables (keeps the partition-filter guarantee);
  **limit** capped at `max_rows` (keeps the row-cap guarantee).
- The compiler only ever emits `select`/`exec`. `system`, `hopen`, `set`,
  `value`, `.z.*`, `.Q.*`, `-N!`, amend, mutation — **cannot be expressed**,
  because the request grammar has no slot for them. The `_DANGEROUS_Q` deny-list
  becomes a belt-and-braces backstop on the *compiled* output, not the primary
  control.

## Coverage without expanding attack surface

The idioms that the free-form proxy rejects become **named structured ops**, each
vetted once in the compiler instead of pattern-matched forever:

| desk idiom | structured form |
|---|---|
| `aj[`sym`time; trades; quotes]` | `{"join":"asof","on":["sym","time"],"left":"trade","right":"quote"}` |
| `wj[…]` | `{"join":"window", …}` (added when needed) |
| `meta trade` | `{"op":"meta","table":"trade"}` |
| `N#select …` | `"limit": N` (already a field) |
| time bars `xbar` | `{"bucket":{"col":"time","size":"00:05"}}` |

New idioms are added by extending the **grammar + compiler** (reviewed, bounded),
not by loosening a regex. Each addition is an explicit goodness grant.

## Layering (unchanged doctrine)

1. **Structured API + compiler** — primary query-plane control (enumerate goodness).
2. **`_DANGEROUS_Q` backstop** on compiled output — defense-in-depth + audit.
3. **Kernel confinement** (non-root q, read-only HDB, no shell, egress-blocked) —
   load-bearing containment; the thing that holds if 1 and 2 are bypassed.
4. **Out-of-process PDP + signed policy + WORM audit** — mediation + record.

## Migration

- Add `run_structured_query(request)` as the agent's query tool; keep `run_query`
  (free-form) available only behind an explicit, default-off policy flag for
  break-glass/admin, never granted to an analyst agent.
- Implement the compiler in `aegis/query_compiler.py` (pure, stdlib, testable);
  reuse the existing date-filter + row-cap injection logic.
- Validate on homer: rebuild the 52-benign corpus as structured requests, confirm
  they compile to the same q the desk expects and run on the FSP gateways; confirm
  the malicious corpus has **no expressible form** in the grammar.
- Acceptance: the structured path covers the real desk corpus with 0 rejects,
  and no request can compile to anything containing a `_DANGEROUS_Q` construct.

## Honest trade-off

A structured API is less expressive than free-form q — some genuinely novel
analytics won't have a structured form on day one. That is the *point*: new
capability is added deliberately and reviewed, not assumed. For the high-value,
high-risk surface (an LLM agent on a prod trading estate), bounded-and-explicit
beats expressive-and-policed.
