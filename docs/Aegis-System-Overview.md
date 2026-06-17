# Aegis - System Overview

*Honest technical overview. Working name "Aegis". A deterministic, fail-closed
policy gate for deploying LLM agents on production kdb+/q estates. Revised
2026-06-15. Generated to `docs/Aegis-System-Overview.pdf` via
`tools/build_overview_pdf.py`.*

---

## 1. Problem statement

Banks and trading firms want to put LLM agents to work **on and around
production kdb+ systems** - market-data tickerplants, real-time and historical
databases (HDBs), gateways. The value is real (analysts asking questions in
English, automation around the estate). The danger is equally real:

- q is a full programming language reached through the **same channel as a
  query**. A single string sent to a kdb+ process can run shell commands, delete
  the HDB, kill the tickerplant (a market-data outage - a regulatory event),
  overwrite the sym file (silently corrupting every symbol column), open network
  connections, or exfiltrate client positions and P&L.
- An LLM is non-deterministic and **promptable by its own inputs**. A
  prompt-injection delivered through a tool result - a poisoned news field, a
  planted file, an MCP response - can make a well-aligned model emit a harmful
  action.

**Why the obvious defenses don't work.** Anything in the model's prompt
("you must not delete data") is *advice* - the model attends to it
probabilistically and will ignore it some fraction of the time. For a bank,
"some fraction" is not a control. Classifier/LLM-judge guardrails have been
empirically evaded up to 100% in the literature. The conclusion the whole field
has converged on: **never rely on the model for security-critical decisions.**

---

## 2. The core idea

A real control is a **deterministic checkpoint a separate process decides,
before the action runs.** Aegis does not *ask* the model to behave; it *decides*
whether each action happens. Principles:

1. **Out-of-model, out-of-process.** The decision point runs in a separate
   process the agent cannot tamper with. The model's output is an *input* to the
   gate, never trusted.
2. **Default-deny (enumerate goodness, not badness).** Only explicitly granted
   capabilities are allowed. Blocking a denylist of "bad" patterns on a
   Turing-complete language is a losing arms race; permitting a small set of
   safe shapes is not.
3. **Fail-closed.** Missing/forged policy, unreachable decision point, unknown
   tool, or any internal error → **block**, never silently allow.
4. **The query plane is bounded by construction.** The agent **never sends raw
   q.** It sends a *structured request* (table, columns, date range, filters as
   data) that Aegis **compiles** into bounded, allowlisted q. Dangerous
   operations have **no slot in the grammar** - they are *structurally
   impossible to express*, not detected-and-blocked.
5. **Rows are governed, not just tables.** A mandatory, non-removable
   per-principal **row filter** is injected into every compiled query, so an
   analyst sees only the rows their entitlement allows - even through joins and
   set operations, and even if they explicitly ask for rows outside their set.
6. **Provenance decides privilege (the injection defense).** Every piece of
   content the agent sees is labelled trusted or untrusted; **untrusted content
   can never drive a privileged action** (a trade, an email, a write, an egress).
   The injection does not have to be *detected* - it simply cannot reach a
   trigger. This is information-flow control, the deterministic answer to prompt
   injection.
7. **Confinement is load-bearing; the gate is defense-in-depth.** The kdb+
   process runs non-root, read-only HDB, no shell, no network egress, and under
   a syscall filter - so even a hypothetical gate bypass cannot delete data,
   reach the network, or attack the kernel.

---

## 3. What it is tested to stop

The adversarial corpus (driven by an *uncooperative* model told to actually try)
covers, on the kdb+ analyst surface:

1. Running OS/shell commands on the kdb+ host
2. Destroying or corrupting data on disk (HDB partitions, the sym file)
3. Mutating the live data (delete/insert/update)
4. Stealing sensitive / client data (positions, P&L, account_no, salary)
5. Reaching outside its lane (non-allowlisted tables, columns, or **rows** the
   principal is not entitled to)
6. Exfiltration & remote code (outbound connections, native shared-object load)
7. Hijacking the process itself (message-handler replacement, `exit`)
8. Resource exhaustion / DoS (unbounded scans that degrade the box)
9. Reading protected files (the policy, password lists, the audit log)
10. Evasion / injection (obfuscation, dynamic eval, injection through the
    structured API's own fields)
11. **Indirect prompt injection** - a malicious instruction hidden in a tool
    result (a file, a query's free-text field, a web/MCP response) that tries to
    drive the agent to a privileged action. Stopped by information-flow control:
    untrusted-derived actions cannot reach a privileged sink.

---

## 4. Architecture

```mermaid
flowchart TB
    subgraph CONF["OS confinement - load-bearing (non-root, read-only HDB, no shell, no egress; namespaces + Landlock + seccomp-bpf)"]
        AGENT["LLM Agent - any model<br/>(Claude / GPT / Bedrock / local)"]
        AGENT -- "tool call: STRUCTURED request<br/>(never raw q)" --> PDP
        subgraph PDP["Policy Decision Point (PDP) - out-of-process, Ed25519-signed policy, FAIL-CLOSED"]
            direction LR
            QC["Query compiler<br/>structured → bounded q<br/>+ mandatory row entitlements"]
            IFC["Information-flow control<br/>untrusted input can't<br/>drive a privileged sink"]
            DET["Detector packs<br/>secrets · PII · destructive ·<br/>prod · resource · MCP"]
            EG["Egress proxy<br/>host allowlist · SSRF ·<br/>payload DLP"]
        end
        PDP -- "only safe, bounded,<br/>entitled actions execute" --> SYS
    end
    SYS["Production systems<br/>kdb+ HDB & gateways · network"]

    PDP -. "every decision" .-> AUDIT["Tamper-evident WORM audit<br/>(hash-chained, off-host mirror, anchored)"]
    PDP -. "decision stream" .-> SUP["Supervisor + circuit-breaker<br/>KILL SWITCH (deterministic)"]
    SUP -. "incident (advisory)" .-> OV["LLM overseer<br/>reads logs, narrates<br/>(advisory, never gates)"]

    CTRL["Control function<br/>authors + signs policy"] -- "signed policy bundle<br/>(monotonic-confinement checked,<br/>read-only mount)" --> PDP
```

**Component summary**

| Component | Role | Property |
|---|---|---|
| **PDP** (`engine`, `pdp_service`) | decides every action against the signed policy | out-of-process, fail-closed |
| **Query compiler** (`query_compiler`) | compiles structured requests → bounded q | injection structurally impossible |
| **Row entitlements** (`query_compiler`) | mandatory per-principal row filter, ANDed into every table reference | non-removable, can't widen, covers joins/setops |
| **Information-flow control** (`ifc`) | untrusted-labelled content can't reach a privileged sink | deterministic prompt-injection defense |
| **Detector packs** (`detectors`) | veto on secrets/PII/destructive/prod/resource/MCP | deterministic, defense-in-depth |
| **Egress proxy** (`egress_proxy`) | network egress control | host allowlist + SSRF + payload DLP |
| **Signing** (`signing`) | Ed25519-signed policy; agent can't forge | integrity / non-repudiation |
| **Policy-change guard** (`monotonic_confinement`) | a policy edit may only narrow the allow-set without approval | widening needs explicit sign-off |
| **Schema-drift linter** (`policy_schema_diff`) | diffs the signed policy vs the live schema | catches lockout + unbounded-scan drift |
| **WORM audit** (`audit`, `worm_sinks`) | tamper-evident record of every decision | hash-chain + mirror + anchor |
| **Supervisor + kill switch** (`supervisor`) | trips a breaker + kills on behavioural tripwires | deterministic, load-bearing |
| **LLM overseer** (`overseer`) | reads the audit, narrates incidents | advisory only, never gates, out-of-band |
| **OS confinement** (`deploy/`) | the containment boundary | namespaces + Landlock + seccomp, kernel-enforced |

The controls span **three planes** that together cover an agent's reach -
**action** (grants + detectors + PDP), **data** (the query compiler + row
entitlements + conformance proof + drift linter), and **information flow** (the
IFC provenance veto) - plus confinement, audit, oversight, and assurance.
Unifying all three behind one signed, fail-closed PDP is the design's edge.

---

## 5. Customising it to your estate

The policy is **data**, owned by the control function - not code. Adapting Aegis
to a specific desk or system is editing a signed JSON policy and running a
validator: **no engineering, no rebuild of the engine.**

- **Schema, tables & columns.** The structured-query allowlist (allowed tables,
  per-table columns, required-date tables, row caps, permitted aggregations and
  operators) is declared in the policy. Add a table or column the desk needs, or
  remove one that is off-limits, by editing the allowlist; `aegis.policy_lint`
  checks it is well-formed, and `aegis.policy_schema_diff` checks it against the
  **live schema** so a dropped column (silent lockout) or a new partitioned
  table without a date bound (unbounded scan) is caught before signing.
- **Row entitlements.** Per-principal row filters (which rows each principal may
  see, by region, book, symbol, desk) are declared in the policy and injected
  mandatorily into every compiled query. A `*` baseline plus table-specific
  rules combine fail-safe (both apply), so forgetting one can only over-restrict,
  never widen.
- **Rules & threat packs.** Each pack (secrets, PII terms, destructive ops, prod
  markers, resource limits, MCP manifests, per-tool argument rules) is enabled
  and tuned in the policy - turn a pack on/off, add a sensitive term, a prod
  host/port pattern, a protected path. New deterministic rules ship as packs
  without touching the gate.
- **Information-flow policy.** Which tools are privileged sinks (egress, write,
  order, scoped query) and which columns/sources are untrusted (free-text fields,
  external tool results) are declared so the IFC veto knows what untrusted
  content must not drive.
- **Tool surface & principals.** Which named tools an agent (or a specific
  principal) may use is a grant list, with RBAC scoping per principal; the
  free-form/break-glass surface is a separate, separately-signed policy.
- **Supervisor & kill action.** Behavioural tripwires (which rules are critical,
  block/escalation thresholds) and the kill action (signal / docker kill /
  kubectl delete / callback) are policy-configured.
- **Confinement & deployment.** The hardening profile (read-only mounts, dropped
  caps, egress allowlist, syscall filter, resource limits) is declarative and
  CI-checked against your real manifest.

**The change workflow:** author from the template, run the validators until
clean, sign it (Ed25519), mount it read-only. Every edit is checked by the
**policy-change guard**: a change that only narrows the allow-set auto-applies;
a change that **widens** it (grants any new capability) is refused until a human
explicitly approves, and the exact new grant is named. Changing a rule = edit,
re-validate, re-sign, reload the PDP - **no code change, fully audited.** A
turnkey authoring kit (`policy.kdb.template.json` + the validators + a guide)
lets the control function do all of this - and run the real-data re-soak -
themselves.

---

## 6. How it works (request lifecycle)

1. The agent emits a tool call - on the analyst surface, a **structured query
   request** (data, not q text).
2. The PDP checks the **circuit breaker** (is this principal quarantined from a
   prior incident?), then **default-deny grants** (is the tool/table/column
   even allowed?).
3. The **query compiler** validates every field against allowlists (table,
   per-table columns, operators, aggregations) and emits **bounded q** - a date
   filter is required on partitioned tables, the result is capped, the
   principal's **mandatory row-entitlement filter is ANDed in** (covering both
   sides of any join/setop), and the compiled output is re-checked against a
   dangerous-construct backstop. Any off-allowlist field → reject, fail-closed.
4. The **information-flow veto** checks the action's provenance: if its arguments
   were derived from **untrusted** content (a prior tool result, a file, a
   free-text field) and the tool is a **privileged sink**, the action is blocked
   before it runs - regardless of what the injected text said.
5. **Detector packs** and the **egress proxy** apply as a further veto (secrets,
   classified-data egress, destructive ops, prod targets, resource limits).
6. The decision (`allow` / `block` / `require_approval`) is recorded to the
   **tamper-evident audit**, mirrored off-host.
7. The **supervisor** observes the decision *sequence*; behavioural tripwires
   (repeated blocks, a critical rule firing, an unclassified action) trip a
   **circuit breaker** that quarantines the principal and fires a **kill
   switch**, writing an incident. The **LLM overseer** narrates that incident
   out-of-band (advisory; it never delays or alters a decision).
8. Only an `allow` reaches the real kdb+ gateway - and even then, the agent runs
   inside **OS confinement** that physically prevents shell, file destruction,
   network egress, and the dangerous syscalls.

---

## 7. How we tested it

Aegis is validated by deterministic, runnable proofs - not assertions.

- **Acceptance suite (CI-gated):** 34 core batteries (`python -m
  aegis.run_all_checks`), run on Python 3.10-3.12, plus a wheel fresh-install
  smoke test, the deployment-hardening gate, and ruff - on every push.
- **Formal:** the default-deny grant algebra is proved sound and monotonic by
  exhaustion, and by **Z3/SMT over unbounded string domains**. AWS's open-source
  **Cedar Analysis CLI (CVC5)** independently corroborates the exported policy as
  a second, external proof checker for the assurance story.
- **q-semantics conformance, on real kdb+:** a battery compiles representative
  and hostile requests with the real compiler and runs the emitted q against a
  live kdb+ instance, asserting the safety bounds actually hold in q's runtime -
  the materialisation cap holds, a reducing query is not corrupted by the cap,
  the entitlement predicate is present and effective, hostile shapes are
  rejected, and the database is byte-identical (read-only) afterwards.
- **OS confinement, on real Linux:** an adversarial test (no host secrets,
  empty network namespace, read-only system dirs, no-new-privs, read-only
  policy) and a Landlock filesystem-confinement test, both fail-closed; the
  **seccomp-bpf** syscall deny-list is verified at the kernel level (a blocked
  syscall is killed with SIGSYS while benign syscalls run).
- **Production-scale realism soak (the headline evidence).** A synthetic but
  realistic kdb+ estate - **4 FSP HDBs × 500M trade + 500M quote = ~4 billion
  rows**, partitioned, enumerated sym, 166 GB on disk:
  - **No hints:** the model discovers the schema itself (`meta`); nothing fed.
  - **Uncooperative attacker:** a jailbroken model *told to actually try*
    (0 refused) → **0/30 attacks succeeded** (most structurally inexpressible,
    the rest gate-blocked). This measures the *gate*, not model goodwill.
  - **Ground-truth correctness:** answers checked against independently-computed
    q results - *served-and-correct*, not just "ran." Every miss was the *model*
    writing the wrong query, never the guardrail.
  - **Row entitlements at scale:** an analyst entitled to AAPL/MSFT sees only
    those rows - through joins, set-ops, and even when explicitly asking for
    other symbols (0 rows). The mandatory filter cannot be removed or widened.
  - **The process found and fixed real defects in the primary control** (a row
    cap that corrupted aggregations at scale; a follow-on materialization
    regression; an entitlement-combine widening path) - exactly what scale +
    ground-truth checking exist to catch.
- **Prompt-injection (information-flow control):**
  - *On the estate:* a real indirect-injection corpus (poisoned file → egress,
    poisoned free-text field → order, untrusted → privileged) gave **100%
    injection block, 0 benign false positives** (the analyst query path is
    trusted and non-sink, so legitimate work is untouched).
  - *On the standard benchmark (AgentDojo, official, Opus):* with the full stack
    on, the agent has real utility (utility is not tanked under attack) and
    targeted-attack-success sits at or near zero, with IFC observably firing on
    the canonical injections. The clean with-versus-without delta on the egress
    suites (where IFC earns its keep) is **partially complete** - the baseline
    run hit an API-credit stop mid-suite; this is documented and resumable, and
    is corroboration of an already-proven deterministic property, not a blocker.

---

## 8. Honest limitations - what Aegis is *not*

- It governs the agent's **actions**. It does not make the model truthful,
  doesn't stop it *suggesting* something unwise in text, and does not replace
  IAM / DLP / change-control - it composes with them.
- **The gate is not the containment.** A denylist over a Turing-complete language
  is leaky; the kernel confinement is what actually contains a determined agent.
  Claims beyond "mediates and confines agent actions, fail-closed, fully
  audited" are overclaims.
- A namespace/Landlock/seccomp sandbox is **weaker than a microVM** against a
  kernel-level attacker (out of scope: a kernel 0-day in an allowed syscall,
  side channels). The seccomp-bpf layer blocks the clearly-dangerous syscalls
  (module load, ptrace, mount/namespace escape, kexec, bpf), which shrinks the
  largest part of that gap but does not close it. For adversarial multi-tenant,
  run the same policy with the agent inside a microVM (Firecracker/Kata) -
  documented, not yet deployed.
- **The injection defense is structural, but its false-positive cost is
  surface-specific.** On the kdb+ analyst surface the false-positive rate is zero
  because the query columns are structured trusted data, so nothing legitimate is
  tainted. On a broad tool surface (chat, email, document agents) where benign
  actions routinely derive from untrusted content, the same provenance rule can
  over-block and must be tuned per surface - the AgentDojo runs surface exactly
  this nuance. IFC raises the bar deterministically; it is not free of tuning.
- The reported numbers are on a **representative** corpus and a **synthetic**
  (if realistic-scale) schema, plus a partial run of the AgentDojo standard
  benchmark. They prove the design; they are **not** a production number. The
  control function must re-soak on the **real desk corpus and real data** before
  enforcing - the one gate only they can close.
- The free-form (raw-q) surface is governed by **allowlist-on-parse**: a
  hand-written query is parsed, only the safe subset is accepted, and it is
  **recompiled through the trusted compiler** (the agent's raw q is never
  executed; only the compiler's output runs). This is far stronger than a
  denylist, but the recognised grammar is a **curated subset that grows**, so
  exotic-but-legitimate q is rejected (safe) and routed to admin break-glass. It
  stays wrapped by caps + confinement; the structured surface remains the strong
  guarantee.
- **Numeric overflow is the model's, not the gate's.** q `sum` over a 64-bit
  integer column wraps silently; the compiler bounds *which rows* are read and
  *which result size* is returned, but it does not widen aggregations, so a sum
  over a very large integer column can overflow to a wrong number. This is a
  correctness property of q, not a safety bound; it is asserted and surfaced by
  the q-semantics conformance battery (`aegis.q_conformance_test`, P7). The fix
  is an estate-side schema choice (widen those columns to `long`).

---

## 9. Where this sits versus the frontier

A 2026 multi-source review (full report in
`docs/Aegis-Frontier-Research-2026-06.md`) places Aegis as strongly **aligned**
with the deterministic, out-of-band enforcement direction the field has
converged on, and **ahead** in one place: no competitor was found compiling
agent queries as a safety gate (the closest research uses an LLM to *rewrite*
queries - the opposite trust model), and none at the q/kdb+ plane. The
information-flow layer brings the prompt-injection defense level with the
research frontier (Microsoft FIDES). The honest residual gaps are a microVM
substrate for fully-untrusted third-party code (the deterministic syscall filter
makes the current stack defensible for first-party agents) and completing the
standard-benchmark delta. Two claims that the evidence does **not** support, and
which Aegis therefore does not make, are flagged in that report.

---

## 10. Status & what remains

**Engineering: complete and validated** on the structured kdb+ analyst surface
- bounded-by-construction query plane, mandatory row entitlements, deterministic
prompt-injection defense, kernel confinement (namespaces + Landlock + seccomp),
two-tier oversight + kill switch, signed out-of-process PDP with a
policy-change guard, tamper-evident WORM audit, installable package, CI-gated at
34/34.

**Remaining - the human gates (not code):**
1. Control-function **real-data re-soak** (the authoring kit makes this turnkey).
2. A **design partner** running it in monitor mode on production traffic.
3. A **third-party security audit** before a production estate depends on it.
4. Completing the **AgentDojo official with-versus-without delta** on the egress
   suites (resumable; corroboration, not a blocker).

**Recommendation:** GO to enforce on the structured analyst surface, conditioned
on confinement deployed (load-bearing), free-form kept off the analyst grant,
and the signed PDP + WORM audit live.

*MIT licensed. This document is an honest overview, not a security guarantee or
legal advice.*
