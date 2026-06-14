# Pilot assessment — honest stage read (2026-06-14)

Where the FSP pilot actually stands, written to be shown to a reviewer/control
function without overselling. Stage: **monitor-mode pilot on sample stacks** —
not production, never touched by a real user.

## Genuinely solid

- **A real false-positive number on real gateways.** 0 gate false positives
  across 156 benign task-runs on a live 4-stack TorQ FSP estate, three models,
  full measure→tune→re-measure loop. This is the artifact that could not be
  produced in a dev sandbox.
- **Two real bugs only real-q testing surfaced — one critical.**
  (1) `select[N]` throws `nyi` on partitioned HDBs, so the proxy's row cap was
  emitting queries the DB rejects — its core guarantee was broken on every real
  historical DB. (2) `select sh:system "id" from trade` ran **shell on the kdb
  host** through a "read-only" proxy (proven: returned a uid). Both fixed.
- **Confinement enforces at the kernel on real Linux** — read-only system dirs +
  Landlock + empty netns (`confine_adversarial_test` 7/7, `landlock_test` 6/6).
  This is the layer to trust most: enforced by the kernel, not by our regex.
- **The out-of-process plane works** — signed bundle, fail-closed when the PDP
  is unreachable, hash-chained + mirrored tamper-evident audit.

## What we will NOT oversell

1. **The gate/proxy are a deny-list on a Turing-complete language.** q reaches
   the OS, files, network and its own handlers many ways; we block the ones we
   enumerated. Enumerate-badness on a full language is leaky — there are almost
   certainly constructs we haven't blocked (every review round found more). Per
   our own doctrine: **the gate raises cost and gives an audit trail; the kernel
   sandbox is the containment.** Do not market the gate *as* the containment.
2. **Recall is partly circular.** "15/15 in-scope" is against attacks we
   authored, with a policy partly tuned to them — and the models *self-refused*
   most attacks, so model safety training carried much of the load, not our
   gate. A jailbroken/open model removes that layer and would subject the gate
   to attack volume we have barely tested.
3. **"0% FP" is on a synthetic corpus** — our analyst questions, the FSP sample
   schema, two days of 2015 data. Encouraging, not "0% in production." Real
   desks run messier multi-table queries, many of which the proxy currently
   *rejects outright* (the coverage gap) — a usability wall on day one.
4. **`kdb_guard` is unproven in enforce.** It denies common q tokens
   (`get`/`set`/`value`); scoped to query tools, but not yet validated against a
   real query corpus. Flipping it to enforce without that is its own risk.
5. **None of the enforce-readiness gates are met** — widened real corpus,
   control-function policy sign-off, WORM to a real off-host sink, and the
   architecture decision below.

## The architecture signal (the most important takeaway)

The coverage gap (proxy rejects `aj`/`wj`/`meta`/nested-from) and the injection
surface (deny-list on free-form q) are **the same problem**: we accept arbitrary
q text and try to police it with regex. Widening the parser to fix coverage adds
hiding places for bypasses, in the most security-critical file — an arms race we
lose slowly. The fix is to **not accept free-form q at all**: a structured query
API (table, columns, date range, filters-as-data) that the proxy *compiles* into
q. That deletes the coverage gap and the injection surface at once, and turns the
query plane into enumerate-goodness — consistent with the rest of Aegis. See
`docs/STRUCTURED_QUERY_API.md`.

## Bottom line

A credible, honestly-instrumented **monitor-stage** guardrail; two genuine bugs
found (one critical); enforcement plane and kernel confinement proven on real
Linux. This is the right stage to be at. It is **not** "safe to enforce on a real
desk," and the path there is not more regex — it is the structured-query-API
redesign with **confinement as the primary control and the gate as audited
defense-in-depth.**
