# Aegis — control-function brief (one page)

*For the control function / 2nd-line risk owner deciding whether to enforce an
LLM analyst agent on the kdb+ estate. Plain-language summary of the
enforce-readiness scorecard (`pilot/ASSESSMENT.md`).*

## What Aegis is

A deterministic, fail-closed guardrail that sits between an LLM agent and your
kdb+ estate. The agent never gets a database handle or a shell. It can only ask
for a small set of **structured** operations; a separate, signed policy process
decides — before anything runs — whether each is allowed, and records it
tamper-evidently. The model's output is an *input* to the gate, not a trusted
instruction.

## The decision in two numbers (measured on the live FSP estate)

- **It doesn't break legitimate work.** 52/52 real analyst desk tasks served, 0
  rejected, across three models — and 0 of 8 benign tasks blocked in enforce mode.
- **It stops misuse — measured at the gate, not by the model's goodwill.**
  0 of 50 targeted attacks succeeded, driven *directly* at the gate (not relying
  on the model to refuse). Destructive/exfil/shell intents have **no way to be
  expressed** on the analyst surface — they are structurally impossible, not
  merely detected.

## Why "structurally impossible" (the key design point)

The earlier approach let the agent send raw q and tried to block dangerous
patterns — an arms race on a full programming language we kept losing. The
analyst now sends *data* (table, columns, date range, filters), which the
guardrail **compiles** into a bounded, allowlisted query. There is no free-form
query to escape, so injection and data-destruction have no slot. This is the
difference between policing badness and only permitting goodness.

## What carries the risk if a layer ever fails (defense in depth)

1. **Structured query gate** — the analyst can only express safe reads.
2. **Kernel confinement (load-bearing)** — the kdb+ process runs non-root,
   read-only HDB, no shell, no network egress. Even a hypothetical gate bypass
   cannot delete data, open a connection, or reach production. Proven on a real
   Linux host.
3. **Signed policy + out-of-process decision point** — the agent cannot edit or
   forge its own guardrails; the gate fails closed if it can't reach the policy.
4. **Tamper-evident audit** — every decision is recorded, mirrored off-host, and
   truncation/rewrite is detectable.
5. **Automated kill switch** — abnormal behaviour trips a circuit breaker that
   blocks the agent and raises an incident.

## Recommendation

**GO to enforce on the structured analyst surface**, provided: confinement is
deployed (it is load-bearing, not optional); raw-query access is never granted
to an analyst (break-glass/admin only, separately approved); and the signed
decision point + off-host audit are live.

## The one thing only you can sign off

Our false-positive and attack numbers are strong but were measured on a
**representative** corpus against a **sample** schema. Before enforcing on the
live desk, the control function should re-run the measurement on the **real desk
query corpus and real data** — that is the gate only you can close, and it is the
recommended condition of go-live.

## What Aegis is not

It governs the agent's *actions*. It does not make the model truthful, does not
stop it from *suggesting* something unwise in text, and does not replace your
IAM/DLP/change-control — it composes with them. We do not claim the gate alone
is containment; the kernel confinement is. Any claim beyond "mediates and
confines agent actions, fail-closed, fully audited" is an overclaim.
