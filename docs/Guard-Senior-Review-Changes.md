# Guard - changes proposed from senior review (handoff for `kqagent/guard`)

**Purpose.** A senior reviewer pushed on the Guard brief with five points. We ground-truthed each
against the standalone `aegis-guardrails` repo (line-by-line, suite at 34/34 core passing) to separate
"already true and tested" from "needs building" from "deployment property, not gate code."

**For the homer-side Claude:** file/line refs below are from `aegis-guardrails` (this laptop) and will
differ in `kqagent/guard`. For each item, please assess: **(a) already done on your side?** **(b) if not,
feasibility + where it lands.** We think you may have moved past several of these.

Legend: **CLAIM NOW** = true and tested today. **BUILD** = bounded gate-code change. **DEPLOY** = a
deployment/platform property we must not claim as gate code no matter what we build.

---

## Summary table

| # | Capability | Status in `aegis-guardrails` | Action |
|---|---|---|---|
| 1 | Confinement: only route to kdb+ is Guard | PARTIAL (in-process lib, bypassable) | **BUILD** broker + **DEPLOY** net rules |
| 2 | Schema-aware bounding (HDB date vs RDB time-window) | MISSING at runtime (confirmed bug) | **BUILD** |
| 3 | Feedback loop on a "no" | BUILT, one assertion missing | **BUILD** (test only) |
| 4 | Customise knobs (tools/data/net/files/approval/audit) | Mostly BUILT_AND_TESTED | **CLAIM NOW** + small carve-outs |
| 5 | Rollout: shadow mode + widen-from-log | Shadow BUILT; auto-widen manual | **CLAIM NOW** (shadow) + **BUILD** (CLI) |

---

## Resolution status (homer side — TorQ-ops chat gate)

Ground-truthed against the live homer integration and resolved each inconsistency by
**implementing it** (claim now verifiable) or **reframing the brief** (deploy property /
scope). The brief (`TorQ-Ops-x-Guard-brief.pdf`) now claims only what's verifiable.

| # | Item | What we did on homer |
|---|---|---|
| — | **Signed policy** | **IMPLEMENTED.** ed25519-signed chat policies; the gate verifies each detached `.sig` against a pinned pubkey *before* loading compiler/engine; a 1-byte tamper -> gate fails closed (every query/action blocked). Per-stack policies verified too. Private key offline/gitignored. (`aegis_gate.py`, `aegis_policy.*.json.sig`) |
| — | **Watchdog** | **IMPLEMENTED.** Supervisor enabled (`repeated_blocks max_blocks=5`); every gate decision fed to `supervisor.observe`, `is_tripped` checked in `govern`. Verified: 5 blocks trip the persisted breaker, which then halts the agent (blocks even benign calls) until reset. |
| 3 | Feedback on a "no" | **CLAIM NOW** — structured reason+layer+remediation reaches the LLM and it adapts. (Minor tidy: also populate `Finding.remediation`.) |
| 4 | Customise knobs | Tools/data/**column allowlist (on the free-form route too)**/rows/caps/audit = **gate code here**. OS/network/process confinement = **reframed in brief as the operator's deployment layer Guard validates** (not gate code). |
| 1 | Confinement | Brief **scoped** to the verifiable mechanism: the chat agent is an LLM that holds no handle/shell/socket and only emits proposals; the server routes every call through Guard, fail-closed. **REMAINING BUILD:** the *autonomous* agent (`python/agent/tools.py run_kdb_query`) still queries kdb+ ungated — route it through the gate, or keep claims scoped to the chat agent. |
| 2 | Schema-aware bounding (RDB vs HDB) | **REMAINING BUILD.** On homer it works by config (RDB tables simply aren't in `require_date_tables`), not by table-kind awareness. Add `table_kind` + RDB time-window per the plan below. |
| 5 | Rollout | Monitor/shadow mode exists in the engine (CLAIM NOW for the engine). **REMAINING:** expose an `AEGIS_MODE=monitor` knob in the deployment + `widen_from_log.py` CLI. |

**Net:** the two headline over-claims (signed policy, watchdog) are now true and tested;
the rest are either verified-and-kept or honestly reframed in the brief. Open builds:
agent-side query gating (#1), schema-aware RDB bounding (#2), monitor-mode knob + widen CLI (#5).

---

## 1. Confinement - "the agent can't bypass Guard to reach kdb+" (the senior's main point)

**Finding.** Not true today. The query proxy (`query_proxy.py` `QueryGuard`) is a pure in-process Python
library the agent's own executor *voluntarily* calls (`live_kdb_agent.py:84` `self.query_guard.enforce(query)`),
so an agent that writes its own connector never calls it. seccomp deliberately permits `socket/connect/bind`
(`seccomp_confine.py:16,73-118` - a legit python+kdb client needs them). No deploy config even names kdb+
as a destination. `THREAT_MODEL.md:159` already admits the in-process placement is "agent-tamperable."

**BUILD (gate code).** Promote the query proxy from an in-process library to an **out-of-process kdb broker
daemon** - new `aegis/kdb_broker.py`, mirroring `egress_proxy.py`'s `ForwardProxy`. The broker holds the
*only* kdb+ handle, speaks kdb+ IPC, and runs `QueryGuard.enforce` on every inbound query. The agent gets no
kdb+ credentials or handle, so it cannot bypass by writing its own connector.
- Tests: new `aegis/kdb_broker_test.py` (broker enforces QueryGuard end-to-end); extend
  `confine_adversarial_test.sh` with a kdb-port case asserting a raw `connect()` from the agent's
  sandbox/segment to the kdb+ port is refused. This turns `confinement_test.py`'s descriptor-string check
  (`confinement.py:70` only asserts the annotation string `== "deny-all-except-proxy"`) into a real control.

**DEPLOY (do not claim as gate code).** `k8s.yaml` NetworkPolicy must name the kdb+ IPC port as DENIED to the
agent and place kdb+ on a control-only segment (`docker-compose.yml` currently defines no kdb+ service at all).
NetworkPolicy / segment enforcement is platform-side. We claim "the broker holds the only handle"; we say the
network boundary is the operator's to apply.

**Homer check:** do you already have an out-of-process gateway/broker holding the kdb+ handle? If so, this is
"align/port," not "invent."

## 2. Schema-aware bounding - HDB date filter vs RDB time-window (CONFIRMED BUG)

**Finding.** The compiler unconditionally stamps a `date=` predicate for `require_date_tables`
(`query_compiler.py:414-430`, `query_proxy.py:211-216`), but a real-time/RDB process has no `date` column, so
that query type-errors. Today the mismatch is caught only by a static policy lint (`policy_schema_diff.py:160-163`
`DATE-NOT-PART`), and the pilot routed around it by pinning a default HDB partition (`SOAK_RESULTS.md:19`).
There is no runtime notion of an RDB target and no test exercises RDB behaviour.

**BUILD (gate code).**
- Add a per-table process model to policy + `QueryCompiler.__init__` (`query_compiler.py:80-103`):
  `table_kind: {table: "hdb"|"rdb"}`, optional per-table `time_col` (default `"time"`) and `default_window`
  (e.g. `"0D00:05"`).
- Branch in `_where_expr` (`query_compiler.py:414-458`): HDB keeps the `date` predicate + partition-span cap;
  RDB injects a bounded **time-window** predicate (`<time_col> > .z.p - <window>`, reusing the magnitude-cap
  logic at `query_compiler.py:176-186`) and **REJECTS** a `date` object against an RDB table.
- Mirror on the lift+recompile path in `query_proxy.py`. Make `require_date_tables` derivable from
  `kind=hdb` (or keep both with a consistency check).
- Tests (`query_compiler_test.py`, `freeform_q_test.py`): RDB-kind -> time-window + `i<N`, no `date=`;
  `date` on RDB -> REJECT; HDB-kind -> still date-bounds. Optionally extend `q_conformance_test.py` to execute
  the RDB form against a non-partitioned in-memory seeded table.

**Homer check:** on the real estate you already hit this (no `date` on the intraday RDB). Have you since made
the bound process-aware, or are you still pinning a default partition?

## 3. Feedback loop on a "no"

**Finding.** Effectively built. A block returns a structured `Decision`/`Finding` with `rule_id` + reason +
remediation (`model.py:85-134`, populated on every block path in `engine.py`); `guard.py:106-115`
`refusal_text()` builds the model-facing "BLOCKED BY POLICY: ...; Allowed alternative: ..." string;
`REQUIRE_APPROVAL` is a first-class pause (`sdk.py:67-89`, `hook.py:58-94`). The aggregated reason carrying
rule prefixes IS asserted (`sdk_test.py`, `budget_test.py`); dangerous calls are proven never to execute
(`example_api_loop.py`). **CLAIM NOW.**

**BUILD (test only).** The exact output string of `refusal_text()` is exercised but never asserted. Add to
`example_api_loop.py` (or a tiny CORE test): for the exfil/secret block cases assert
`refusal_text(...).startswith("BLOCKED BY POLICY:")` and, when a finding has remediation, that the string
contains `"Allowed alternative:"` + the remediation substring. Plus a no-leak test: build a `Decision` whose
`Finding.evidence` is a sentinel secret and assert that sentinel is absent from `refusal_text()` output
(enforces the `guard.py:108-110` docstring promise).

## 4. Customise knobs - mostly real

**CLAIM NOW (enforced and tested):** tools (default-deny, proved exhaustively by `formal.py:117-124`); data -
tables, columns (structured path), rows (mandatory non-removable per-principal entitlement filter,
`query_compiler.py:375-412`, 16-case test), row caps, date windows; network destinations (real `ForwardProxy`
daemon + tests); file paths; approvals (fail-closed); soft kill-switch (circuit breaker, `supervisor.py`,
8 scenarios); off-host audit delivery (WORM sinks, strict fail-closed).

**BUILD / carve-outs (do not over-claim until done):**
- **Hard kill-switch** (signal/command in `supervisor.py:172-187`) - paths exist but only the `callback`
  strategy is tested. Add `supervisor_test.py` cases: spawn a throwaway subprocess, assert `strategy="signal"`
  terminates it; `strategy="command"` against a stub.
- **cpu/memory/pids limits** - **DEPLOY today.** `confinement.py:88-91` only checks the JSON descriptor keys
  are truthy; no OS enforcement in Aegis. To make it gate code: new `aegis/deploy/rlimit_confine.py`
  (`resource.setrlimit` RLIMIT_AS/NPROC/CPU, mirror `seccomp_confine.py`), wired into `run_all_checks` CORE,
  with a fork test proving a child OOMs/forkbombs/CPU-caps under the limit. Container/k8s caps stay DEPLOY.
- **seccomp SIGSYS kill** - Linux-only. The kernel half SKIPs on Windows (`seccomp_test.py:142-149`); only BPF
  well-formedness is proven off-Linux. Present as Linux-only or add a Linux CI lane. (Note seccomp is a syscall
  deny-list, not a cpu/mem cap, and deliberately permits sockets - do not conflate with kdb+ confinement.)
- **Column allowlist** is enforced only on the structured-compiler route (`query_compiler.py:152-163`), not on
  the free-form regex `QueryGuard`. Either enforce columns in `query_proxy.py` or scope the "customise columns"
  claim to the structured-API deployment.

## 5. Rollout - shadow mode + widen-from-log

**CLAIM NOW (shadow half).** A tested "monitor" mode runs the full default-deny policy, downgrades the enforced
effect to ALLOW while recording the would-be verdict (`engine.py:178-181`, `model.py:99-101`), and is a CORE
check (`monitor.py`). Fail-closed paths (load error, supervisor trip, audit-unavailable) are explicitly NOT
downgraded. Documented rollout discipline exists (`PILOT.md:50-77`: monitor -> measure FP -> flip to enforce).

**BUILD (gate code).** The "widen the grammar from the audit log of legitimate-but-blocked attempts" half is a
*manual* procedure today, not tooling (the one real widening, B18 in `SOAK_RESULTS.md`, was a hand edit;
`monotonic_confinement.py` only *guards* widening, never proposes it). Add a `aegis/widen_from_log.py` CLI that
reads the shadow/audit JSONL, filters would-be BLOCK / REQUIRE_APPROVAL entries, groups by
(tool, binary, table, path-prefix, rejected grammar shape), emits candidate `policy.grants` / grammar diffs, and
feeds them through `monotonic_confinement.guard_policy_update` for narrowing/widening classification + approval
routing. Ship with a `*_test.py` over a synthetic blocked-attempt log.
- Caveat: the engine audit body truncates the target to 200 chars and drops structured args
  (`audit.py:94`); either widen the audited body or consume the soak-style JSONL that already has full args
  (`fsp_soak.py:270-276`).

---

## Do NOT claim as gate code, no matter what we build (deployment properties)

- Container/k8s **cpu/memory/pids** caps (Aegis can validate the descriptor and ship an rlimit guard; the
  container/cluster caps themselves are platform-enforced).
- **NetworkPolicy / network-segment isolation** (the boundary that backs the kdb broker).
- **Off-host audit true immutability** (sink-side property; Aegis proves delivery + strict fail-closed).
- **Out-of-process PDP placement** (deployment-wired; `THREAT_MODEL.md` is honest about this).

## Suggested ordering (cheapest first)

1. Feedback-loop assertion + no-leak test (test only).
2. Hard kill-switch signal/command tests (test only).
3. Column-allowlist: enforce on free-form route or scope the claim.
4. `rlimit_confine.py` + fork test (real cpu/mem/pids as gate code).
5. **Schema-aware bounding** - the confirmed bug fix (#2).
6. `widen_from_log.py` CLI + test.
7. **kdb broker** (#1) - the architectural piece; plus deploy net rules (DEPLOY).
