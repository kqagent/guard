# Cedar evaluation — adopt, bridge, or differentiate?

*2026-06-12. Decision record for the question raised by the competitive
research: should Aegis adopt AWS Cedar as its policy language instead of
the bespoke `policy.json`?*

## What Cedar is (verified)

- Open-source authorization policy language + Rust engine, originated at
  AWS, now a CNCF project. Formally verified implementation (Lean proofs;
  arXiv:2403.04651): default-deny, forbid-overrides-permit,
  order-independent evaluation, O(n) bounded evaluation time, no loops or
  side effects by design. Built for automated reasoning: Cedar Analysis
  can prove a policy set contradictory, overly permissive, or equivalent
  to another — at authoring time.
- **Amazon Bedrock AgentCore Policy (GA March 2026)** is the heavyweight
  competitor built on it: a Cedar PDP inside AgentCore Gateway, gating
  agent→tool (MCP) calls, default-deny, with a schema generator that turns
  MCP tool descriptions into a Cedar schema so policies are validated
  against real tools/parameters, and an LLM→Cedar natural-language
  authoring loop checked by Cedar Analysis.
- **Python story (the catch):** the engine is Rust. `cedarpy` (PyO3
  bindings) exists but is early-stage and explicitly *not* supported by
  AWS or the Cedar team. There is no stdlib-compatible Cedar evaluator.

## The constraint that decides it

Aegis's enforcement path is **stdlib-only on purpose**: the gate must
never fail open (or fail at all) because a third-party package — let alone
an unsupported native extension — failed to import. Putting cedarpy in
the decision path violates the project's core doctrine for a dependency
whose maintenance we don't control. That rules out wholesale adoption
(Option A) today, independent of any feature comparison.

The feature comparison also matters: Cedar answers *"may principal P do
action A on resource R given context C?"* — exactly our grants / rbac /
tool_rules / mcp_manifest algebra, and it answers it better-analyzed than
we do. But most of Aegis is **not** that question:

| Aegis layer | Expressible in Cedar? |
|---|---|
| grants (tools/binaries/writable paths) | yes — natural fit |
| rbac, tool_rules, mcp_manifest | yes — natural fit |
| secrets / DLP content detectors | no — content scanning, not authz |
| query proxy (parse + **rewrite** unsafe q/SQL) | no — Cedar decides, never rewrites |
| egress proxy (SSRF, payload DLP) | partially — host allowlist yes, payload scan no |
| cost budgets (stateful ledger) | awkward — context could carry usage, state lives outside |
| approvals workflow, WORM audit, confinement validation | no — out of scope for any authz language |

So even full Cedar adoption would replace roughly a third of the system
and leave the differentiating layers untouched.

## Options considered

**A. Adopt Cedar as the policy language (replace policy.json).**
Rejected for now: unsupported native dep in the fail-closed path; only
covers the authz third of the system; rewrites every battery for no
customer-visible gain.

**B. Cedar-native PDP variant.** Run the Cedar engine inside
`pdp_service` (the out-of-process sidecar), where a heavier runtime is
architecturally acceptable — the agent host still talks fail-closed HTTP
to it. Viable later if a customer standardizes on Cedar; the RemotePDP
client and Guard interfaces would not change. Park until demanded.

**C. Cedar export at authoring time (chosen).** Keep the stdlib
enforcement path; add a deterministic translator from `policy.json`'s
authz subset to Cedar policy text (`aegis/cedar_export.py`,
`python -m aegis.cedar_export` writes `policy.cedar`). What this buys:

1. **Analyzability** — the control function can run the exported bundle
   through Cedar Analysis / the Cedar CLI to prove non-contradiction and
   compare policy versions, without Cedar ever entering the decision path.
   (Complements `formal.py`/`formal_smt.py`, which prove OUR engine's
   algebra; Cedar Analysis checks the *policy content*.)
2. **Interop story** — "Aegis speaks Cedar" defuses the AgentCore
   objection in a bank conversation: policies are portable to/auditable in
   the emerging industry dialect, while Aegis stays cloud-neutral.
3. **A migration hedge** — if Option B is ever demanded, the export is
   the compiler front half.

## Positioning vs AgentCore Policy (what to say)

AgentCore Policy validates our thesis at hyperscaler scale: deterministic,
default-deny, out-of-model enforcement at the gateway. We do not beat it
at Cedar-shaped authz, and shouldn't claim to. The defensible line stays
what the research run concluded: **no single product spans tool-authz +
query-plane rewriting + egress DLP + signed WORM audit + confinement
validation, model- and cloud-neutral, with kdb+ depth.** AgentCore covers
plane (b) only, AWS-locked; Satori/Immuta cover plane (c), SQL-only.
"Exports to Cedar" adds: we participate in their ecosystem rather than
compete with its language.

## Decision

- [x] Build `aegis/cedar_export.py` (authz subset → Cedar text, CORE-tested)
- [ ] Re-evaluate Option B when a prospect requires a Cedar-native PDP
- [ ] Track cedarpy/Cedar-CNCF maturity ~quarterly; revisit A only if an
      official, supported Python evaluation path appears
