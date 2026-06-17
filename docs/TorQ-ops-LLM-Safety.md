# Letting an LLM investigate a live TorQ-ops stack — without it harming prod

*Tailored to TorQ-ops. Explains both controls — the code-quality gate (kqagent)
and the production safety gate (Aegis) — what each stops, how, and the exact tech.*

---

## The question (from the TorQ-ops demo)

> "When the LLM goes to investigate an issue on a production server and starts
> writing code or queries to figure out what happened — how do we stop it
> harming the system with **bad code or poorly written queries**? It could bring
> down a tickerplant, OOM the box, delete data, block the gateway."

It's the right question, and the honest answer has **two distinct parts**, because
there are **two distinct risks**:

| Risk | Example on a TorQ-ops stack | The control |
|---|---|---|
| **A. Poorly written / incorrect q** (a *quality* problem) | A diagnostic query does `select from trade where sym=\`AAPL` with no date — kdb+ memory-maps every HDB partition and the box goes `wsfull`/OOM. Or `where venue="XNYS"` throws `'length` and the investigation gets a wrong answer. | **kqagent** — the code-quality gate |
| **B. Dangerous / unauthorised action** (a *safety* problem) | The agent runs `system "kill ..."`, `delete from`, overwrites a TP log, sends a blocking sync to the gateway, or reads data it shouldn't. | **Aegis** — the production safety gate |

Banks worry about both. The mistake is to think one tool covers both. **kqagent
makes the q *good*; Aegis decides what the agent is *allowed to run* and bounds
it.** Below, exactly how each works, and how they combine.

---

## The TorQ-ops scenario we'll trace

A TorQ stack (say the `FX` stack) has processes: **tickerplant (TP/STP), RDB, HDB,
WDB, sortworker, gateway**. TorQ-ops monitors them and stores operational data in
kdb+ tables: `logmessages`, `querylogs`, `monitorstats`, `metrics` (unified
long-format with a `val` column), `systemstats`, `processstats`. Analysts/agents
query that data **through the TorQ-ops gateway** (`getmetrics`,
`getqueriesbyuser`, `gethistoricquerytime`, `getqueryconcurrency`,
`getquerycontext`, …) — never by raw IPC into the live TP or RDB.

Incident: **`rdb1` in the `FX` stack went `wsfull` at 14:05.** The agent is asked
to investigate. To do that it will read logs, query latency metrics, look at which
queries were running — i.e. it will **write and run code against a production
system that is already under stress.** That's the danger surface.

---

## Risk A — "poorly written queries / bad code": the **kqagent** quality gate

**What it is.** A deterministic kdb+/q lint engine (the "maze" engine,
`checkKdbLint()`) with **58 rule detectors** (regex + AST), plus a
retrieval-assisted fix loop. It judges whether a piece of q is *well-written and
safe to run* — independent of any model.

**The rules that matter for "won't harm prod":**
- **`KDB-HDB-001`** — a query on a partitioned table whose **first `where`
  predicate isn't the date/partition column** is blocked. This is *the* foot-gun:
  without a date-first predicate, kdb+ memory-maps and scans **every** partition —
  on a multi-year HDB that's the classic OOM/`wsfull` that takes the process down.
  The investigator querying `querylogs`/`trade` history is exactly where this bites.
- **`KDB-QRY-002`** — `=` on a string column (throws `'length`, or silently wrong).
  A wrong diagnostic sends the whole investigation down a blind alley.
- **`resource_guard` / perf rules** — heavy/unbounded constructs flagged.
- 50-odd more covering casts, enumerations, namespace, control-flow, I/O, etc.

**How it actually enforces (three surfaces, same engine):**
1. **Editor hook** (dev convenience while writing code) — *not a control, just shift-left.*
2. **CI / pre-commit** (`tools/ci_gate.py`, `tools/gate.js`) — a **required merge
   check** a developer can't switch off, tool-agnostic. This is where the TorQ-ops
   diagnostic scripts and the codebase itself get gated.
3. **Agent-runtime** — when the deployed investigator writes **free-form q** (a
   custom diagnostic the structured API can't express), `checkKdbLint()` is called
   by the agent's tool executor **before the q runs**. Block-severity violation →
   the q is refused and the agent gets the rule message back.

**The fix loop (why a cheap model is enough).** On a block, kqagent searches a
**38 MB skill index** — ~28.5k chunks across tiers: `scrape` (≈25k verified
external q docs from code.kx.com / q4m3, with source URLs), `skill` (hand-authored
explainers), `rule` (the lint-rule cards). Retrieval is **BM25 over SQLite FTS5**
(column-weighted), with a fine-tuned q encoder, hybrid sparse+dense fusion, a
document graph (PageRank) and a reranker in the broader stack. The retrieved doc is
fed back; the model **refines** until the q passes. Net effect: the agent's q is
corrected to a date-first, bounded, idiomatic query *before* it ever touches `rdb1`.

> **kqagent's job in one line:** make sure any q the agent writes is *correct and
> performant* — so a clumsy diagnostic can't itself become the second outage.

**Honest limit:** kqagent is a *static linter* — it catches the patterns its rules
know. It checks the *form* of the q, not intent (a query can technically satisfy a
rule and still be wide). That's why it is **not the safety boundary** — it's the
quality boundary. The safety boundary is Aegis.

---

## Risk B — "harming the system / unauthorised actions": the **Aegis** safety gate

**The core idea:** on the structured path the agent **does not write q at all** —
it sends a *structured request* (which table, columns, filter, time window) and the
**compiler** emits the only q that runs. This dissolves Risk A *and* Risk B for the
normal investigation path:

- **Poorly-written queries become impossible**: the compiler emits date-first,
  allowlisted, idiomatic q with a mandatory time bound and **result/scan caps** —
  so an investigation query *cannot* full-scan the HDB or OOM `rdb1`. (This is the
  structural version of what kqagent enforces by linting.)
- **Dangerous queries become inexpressible**: `system`, `delete`, `hdel`, `exit`,
  `set`/`save`, `value`/`eval`, `.z.pw` overrides — *none of them are in the
  request grammar.* The agent can't ask for them.

**The full Aegis stack:**

| Layer | What it does on TorQ-ops | Why |
|---|---|---|
| **Structured-query compiler** | Agent sends intent; compiler emits the only q that runs against the gateway, validated + bounded | Bad/dangerous q is *inexpressible*; queries can't OOM `rdb1` |
| **Row-level entitlements** | Mandatory per-principal row filter (e.g. only the `FX` stack's data), default-deny | Agent sees only what it's authorised to; can't widen |
| **Resource caps** | Mandatory time bound + per-partition + global result caps | A diagnostic can't exhaust the process it's inspecting |
| **Deny-list backstop** | Re-scans compiled output for dangerous tokens | Defence in depth behind the compiler |
| **Detector packs** | `kdb_guard`, `resource_guard`, `pii_egress`, `secrets`, `prod_protection`, `destructive_ops` veto | Catch anything outside the modeled-safe surface |
| **IFC (information-flow control)** | Untrusted-derived input (a poisoned `logmessages` row) can't drive a privileged action | A malicious/garbled log line can't make it restart a process |
| **Grants + signed policy** | Default-deny capability allowlist, Ed25519-signed | The agent only has the tools it was granted |
| **Out-of-process PDP** | Decision by a separate signed service; fail-closed | Model can't reach around the decision; outage = block |
| **3-tier remediation autonomy** | *auto* (stateless restart) / *human-approval* (restart `rdb1`) / *never* (touch gateway or STP) | Bounds the blast radius of *actions* |
| **Kernel confinement** | Landlock + seccomp + read-only rootfs around the agent process | Even a gate bug can't let it reach prod another way |
| **WORM audit** | Hash-chained tamper-evident decision log | Every decision reviewable for compliance |

> **Aegis's job in one line:** decide what the agent is *allowed to run* against
> the live stack, bound it so it can't exhaust a process, make dangerous actions
> impossible, and confine the process so it can't reach prod except through the gate.

---

## How an investigation actually flows (and where each control fires)

1. **Agent is confined** (Landlock/seccomp/read-only rootfs): its only route to the
   `FX` stack is the Aegis-gated tool. No shell, no raw IPC to the TP/RDB. *(Aegis)*
2. **Agent reasons and issues a structured request:** *"slowest queries on `rdb1`,
   14:00–14:10."* It's intent, not code. *(Aegis)*
3. **Authorize:** default-deny grants (is it allowed this tool?) + row entitlement
   (only `FX` data). *(Aegis)*
4. **Compile:** validated, time-bounded, capped q emitted against the gateway.
   *Poorly-written / unbounded queries can't be produced here.* *(Aegis — subsumes Risk A on this path)*
5. **Veto:** detector packs + IFC (a poisoned log row can't drive an action). *(Aegis)*
6. **Decide + audit:** deterministic allow/block, WORM-logged. *(Aegis)*
7. **Run read-only via the gateway**, capped result returns. The agent reasons,
   issues the next structured request. *(Aegis)*
8. **If the diagnostic needs free-form q** (something the structured API can't
   express): the agent writes actual q → **kqagent lints it** (blocks a full-scan
   or string-`=`, RAG-fixes it) for *quality*, and **Aegis's deny-list + detectors
   + caps + confinement** still wrap it for *safety*. Both fire. *(kqagent + Aegis)*
9. **If it wants to act** ("restart `rdb1`"): the **3-tier autonomy** policy gates
   it — `rdb1` restart needs human approval; touching the gateway/STP is never
   allowed. *(Aegis)*

So: on the **normal path**, Aegis's compiler makes both "bad query" and "dangerous
action" impossible. On the **free-form path** (real code), **kqagent guarantees the
code is well-written and won't OOM**, and **Aegis guarantees it's allowed, bounded,
and confined.** Neither alone is the full story; together they are.

---

## The two controls, side by side

| | **kqagent** | **Aegis** |
|---|---|---|
| Question it answers | *Is this q well-written and performant?* | *Is this action allowed, bounded, and safe to run on prod?* |
| Risk it removes | poorly-written / incorrect q (wrong answers, accidental full-scan/OOM) | destructive or unauthorised actions; resource exhaustion; injection; data over-reach |
| Mechanism | 58-rule lint engine + RAG fix loop | structured compiler + entitlements + caps + IFC + detectors + signed PDP + confinement |
| Determinism | gate deterministic; model used only to *fix* | fully deterministic; **no model in the enforcement path** |
| Where it runs for prod | CI merge gate + free-form-code lint in the agent's tool executor | the agent's runtime tool/query layer (the chokepoint to the estate) |
| Failure it prevents | a **bug** (the query is the second outage) | a **breach** (the agent breaks or exfiltrates prod) |

---

## Honest boundaries (say these — they're what make it credible)

- The **strong** guarantee is the **structured path**: dangerous and unbounded q
  are *inexpressible*, and queries are correct + capped by construction. The
  **free-form path** (real q the agent authors) is the weaker case — there,
  kqagent's lint is *enumerate-the-known-bad* and Aegis's deny-list likewise; both
  are wrapped by resource caps and OS confinement, and the path is gated behind
  approval. We don't claim the free-form path is airtight; we claim it's bounded
  and confined.
- The whole thing holds **because the agent can only act through the gated layer**,
  which kernel confinement *enforces*. The one architecture you must not ship is
  raw shell / direct IPC to a prod process.
- These are **proven where we can prove them** (exhaustive over the modeled space,
  Z3 for unbounded domains, AWS Cedar corroboration), measured on the **AgentDojo**
  injection benchmark, and red-teamed at **0/50** attack-success on a real
  **4-billion-row** estate. That is strong evidence — not a claim that no attack
  can ever exist.

---

## Bottom line for the client

> When the LLM investigates a TorQ-ops incident, it can only act through a gate it
> can't see around. Normally it doesn't write queries at all — it states what it
> wants to look at, and the compiler emits correct, time-bounded, capped q against
> the gateway, so a poorly-written query that OOMs `rdb1` can't be produced and a
> destructive command can't be expressed. If a diagnostic genuinely needs hand-written
> q, **kqagent** lints it so it's correct and won't full-scan the box, and **Aegis**
> bounds and confines it so it can't harm the stack. Any restart or state change needs
> a human by policy; touching the tickerplant or gateway is never allowed; the agent's
> process is OS-confined; and every decision is deterministic and audited.
>
> **kqagent stops the bad *code*. Aegis stops the bad *action* and bounds everything.
> Together, a bank can let an LLM investigate a live stack without it being able to
> break the stack.**
