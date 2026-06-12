# Aegis target architecture

Reflects the four committed design decisions:

| Decision | Choice |
|---|---|
| Execution substrate | **Mix** — containers/K8s for operational agents, laptops for dev assist (tiered guarantee) |
| PDP placement | **Out-of-process** sidecar/service (agent cannot tamper) |
| Posture | **Default-deny everywhere** (allowlist capabilities; detectors are veto layer) |
| Data plane | **Egress proxy + query proxy** (enforce at ground truth) |

## Target diagram

```
        UNTRUSTED                         TRUSTED (separate privilege)
 ┌──────────────────────┐
 │  LLM (any provider)  │
 │  agent reasoning     │
 └──────────┬───────────┘
            │ tool-call request (the ONLY way out)
 ┌──────────▼───────────┐        ┌──────────────────────────────┐
 │   BROKER (chokepoint │  IPC   │   PDP sidecar  (pdp_service)  │
 │   by construction)   │───────►│   default-deny + detectors    │
 │   sole execution path│◄───────│   signed policy (RO mount)    │
 └──────────┬───────────┘ verdict└───────────────┬──────────────┘
            │ allow only                          │ every decision
   ┌────────┴─────────┐                 ┌─────────▼──────────┐
   │ confined runtime │                 │  append-only WORM  │
   │ (L1 sandbox)     │                 │  audit sink        │
   └───┬─────────┬────┘                 └────────────────────┘
       │         │
  ┌────▼───┐ ┌───▼─────┐
  │ egress │ │  query  │   ← L4 enforce at ground truth
  │ proxy  │ │  proxy  │
  └────────┘ └─────────┘
```

The agent has **no** direct network, no direct shell, no direct DB handle. Its
only capability is "ask the broker." Default-deny means the broker runs nothing
unless the signed policy explicitly grants it.

## Decision flow (default-deny)

```
action ─► PDP:
   load_error?            ─► BLOCK (fail-closed)
   detector veto (block)? ─► BLOCK
   matches a grant?  no   ─► BLOCK (default-deny: no capability)
                     yes  ─► detector says approval? ─► REQUIRE_APPROVAL
                                              else    ─► ALLOW
```

A capability **grant** declares what is allowed: tools, shell binaries,
writable paths, egress hosts, queryable tables. Anything not granted is denied.
Detectors (the eight packs) still apply as a **veto** on granted actions — e.g.
`git` is granted, but `git push --force` is vetoed.

## Components

| Component | Status | Module |
|---|---|---|
| Decision model | ✅ | `model.py` |
| Engine (now default-deny + grants) | ✅ | `engine.py` |
| Detector packs (veto layer) | ✅ | `detectors.py` |
| Tamper-evident audit | ✅ | `audit.py` |
| **Out-of-process PDP** sidecar | ✅ backbone | `pdp_service.py` / `pdp_client.py` |
| Broker chokepoint | ✅ (in-proc form) | `guard.py` |
| Claude Code adapter | ✅ | `hook.py` |
| Input-side proxy (redaction/model allowlist) | ✅ skeleton | `proxy.py` |
| **Egress proxy** (L4, host allowlist + SSRF + payload DLP) | ✅ | `egress_proxy.py` |
| **Query proxy** (L4, kdb/SQL parse + limit inject) | ✅ | `query_proxy.py` |
| Red-team evasion corpus | ✅ | `redteam_corpus.py` |
| Policy signing + pinned-key verify (Ed25519) | ✅ | `signing.py` |
| Confinement validator + reference manifests | ✅ | `confinement.py`, `deploy/` |
| Read-only mount of policy/engine/audit (OS) | ✅ in manifest | `deploy/k8s.yaml` |
| Tamper-proof audit (mirror + anchor, truncation-detect) | ✅ | `audit.py` |
| Red-team evasion corpus (CI) | ▢ phase 2 | — |

## Per-surface guarantee (the "mix" honesty)

| Surface | Substrate | PDP | Guarantee |
|---|---|---|---|
| Operational / prod agent | container/K8s, confined | out-of-process sidecar | **watertight** — confinement + default-deny + proxies + RO policy |
| Dev coding assist | laptop, Claude Code | out-of-process local PDP | **strong defense-in-depth** — cannot fully sandbox a laptop; be explicit |

We never tell the bank a laptop surface is watertight. It gets default-deny +
detectors + audit, which is strong, but L1 confinement is partial there.

## Competitive positioning (validated by research)

The market has independently converged on this architecture — deterministic,
out-of-process, default-deny, model-independent enforcement (CoSAI/OASIS;
classifier guardrails shown evadable up to 100%, arXiv:2504.11168). Production
tooling splits into three planes and **no single competitor spans all of them:**

- **Content / IO filtering** — AWS Bedrock Guardrails, Azure AI Content Safety, Lakera.
- **Tool-call authorization** — AWS Cedar / Bedrock AgentCore (deterministic,
  formally verified, GA): the closest peer to our PDP.
- **Data / query plane** — Satori (rewrites SQL to inject row filters), Immuta
  (native DB row/column policies).

Honest novelty: the query-proxy *mechanism* already exists for SQL stores
(Satori/Immuta), so it is NOT unclaimed white-space. Our differentiation is
**(1)** unifying all three planes + egress + signed audit + confinement in one
default-deny pipeline for the agent, **(2)** the kdb+/q target no SQL-governance
proxy supports, and **(3)** the financial-services wrapper. Where peers lead:
Cedar/AgentCore is formally verified — adopting Cedar as the policy language is
a roadmap option; our proof is currently exhaustive (bounded), not SMT.

## Compliance posture (primary-source verified)

- **EU AI Act** (binding for high-risk systems): Art. 12 event logging → the
  tamper-proof audit; Art. 14 human oversight → the require-approval path;
  Art. 15 robustness/cybersecurity → red-team + signing + fail-closed. Article
  text verified verbatim.
- **Fed SR 26-2** (Apr 2026) supersedes SR 11-7 and places generative/agentic AI
  *outside* model-risk-management scope — so this is positioned as the
  operational governance control such tools still require, **not** MRM
  compliance. See `compliance.py` (self-verifying crosswalk).

## Phased roadmap

- **P0 (done):** decision model, engine, packs, audit, adapters, demos, threat model.
- **P1 (this step):** default-deny engine + grants; out-of-process PDP + client; fail-closed on PDP-unreachable.
- **P2:** egress proxy + query proxy (ground-truth enforcement); policy signing + pinned-key verification; WORM audit sink; red-team evasion corpus in CI; monitor-mode rollout + FP metrics.
- **P3:** broker SDK for platform-API apps (tools registered behind the broker, not callable directly); approval-workflow backend; per-principal RBAC + cost/rate budgets; container admission policy.
```
