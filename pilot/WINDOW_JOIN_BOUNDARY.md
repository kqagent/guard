# Window-join (wj) — boundary decision (item B2)

**Decision: document the boundary and skip — do not ship a `wj` grammar slot now.**

Per the brief: "Add as a reviewed structured op *if the desk corpus needs it* … If
the desk doesn't need it, document the boundary and skip — don't add surface for
its own sake."

## Why skip

- **Demand is a single corpus shape.** Across the 52-task desk corpus, exactly one
  (B30, average prevailing bid/ask in a ±0.5s window around each trade) needs
  `wj`. Coverage without it is 51/52.
- **The slot would be the riskiest in the compiler for the least return.** `wj`
  needs a window-pair matrix `(w1;w2)` of bracket offsets *and* a right table that
  is sorted and ``g#``-keyed on the join column; getting that construction wrong
  fails open (wrong numbers) rather than closed. That is more surface, in the
  most security-critical file, for one query.
- **It cannot even run here.** The FSP gateway already times out on `aj` at
  partition volume (federated-HDB perf, noted in earlier iterations). A `wj` slot
  could compile but would be unrunnable on this estate — so we couldn't validate
  it live, which is exactly the bar the other grammar slots cleared.

## What the desk does instead, today

The bounded approximation is already expressible: bucket trades and quotes into
fixed time bars (`bucket`) and join the per-bar aggregates with the existing
`asof`/`left` join. That answers "prevailing quote near a trade" at bar
granularity without `wj`.

## When to revisit (the reviewed path)

Add `wj` as a structured slot when **a real desk requires sub-bar window joins on
a runnable gateway**, with: both sides validated and date-bounded; join key
allowlisted on both tables and the right side proven ``g#``-sorted; the window
expressed as a typed bounded pair (e.g. `{"window":{"before":"00:00:00.5",
"after":"00:00:00.5"}}`), never free-form; an abuse test proving no `_DANGEROUS_Q`
construct is expressible and the window literals can't break out of the timespan
type. Until then, the boundary is honest: **51/52, wj out of scope.**
