# Aegis — guardrails an LLM agent cannot ignore

> Working name. A deterministic, fail-closed policy gate that lets an
> investment bank deploy LLM agents into production with hard controls the
> model provably cannot bypass — across coding *and* operational agents, with
> any model (Claude Code, Anthropic/OpenAI/Bedrock API, or behind a gateway).

```
python -m aegis.run_all_checks      # the whole thing, proven in one command
```

## The one idea

Anything in an LLM's prompt — instructions, warnings, "you MUST not…" — is
**advice**; the model attends to it probabilistically and will ignore it some
fraction of the time. For a bank, "some fraction" is not a control.

A real control is a **deterministic checkpoint a separate process decides,
before the action runs.** It doesn't *ask* the model to behave; it *decides*
whether the action happens. And "watertight" is not a better denylist —
pattern-matching is always evadable. Watertight means **enumerate goodness**
(default-deny, least privilege), make whole attack classes *impossible* via
confinement, and use the policy engine as defense-in-depth + audit + the
human-approval router. No single layer is trusted; the stack is.

The honest claim: *the agent cannot exceed the capabilities the control
function granted it, every attempt is mediated and logged, and anything
ambiguous is escalated to a human.*

## The stack — and the test that proves each layer

| Layer | What it does | Module | Proof |
|---|---|---|---|
| L1 Confinement | sandbox: read-only FS, no direct net, no creds, limits — verified by a deterministic validator | `confinement.py`, `deploy/` | `confinement_test` |
| L2 Broker + MCP manifests | tool calls are brokered; each MCP server is zero-privilege until its manifest grants tools | `guard.py`, `mcp_manifest` | `example_api_loop`, `mcp_test` |
| L3 Default-deny PDP | allow only granted capabilities; out-of-process; fail-closed | `engine.py`, `pdp_service.py` | `pdp_test`, `demo`, `formal` |
| L4 Query proxy | parse kdb/SQL, inject date filter + row cap, reject unsafe | `query_proxy.py` | `query_proxy_test` |
| L4 Egress proxy | real-destination allowlist + SSRF guard + payload DLP | `egress_proxy.py` | `egress_proxy_test` |
| L4 Named-tool rules | per-tool argument policy for function-calling agents | `tool_rules` | `agentdojo_eval` |
| L5 Integrity | Ed25519-signed policy, pinned key, read-only mount | `signing.py`, `deploy/k8s.yaml` | `signing_test` |
| L7 Audit | hash-chained + off-host mirror + anchor (truncation-proof) | `audit.py` | `audit_worm_test` |
| L8 Assurance | exhaustive formal proof; adversarial corpus; shadow FP/recall; self-verifying compliance crosswalk | `formal.py`, `redteam_corpus.py`, `monitor.py`, `compliance.py` | `formal`, `redteam_corpus`, `monitor`, `compliance`, `agentdojo_eval` |

Every row is a passing, deterministic test. `run_all_checks` runs all 15.

## Why it can't be ignored

- **Decision is outside the model's loop** — PreToolUse hook / broker / PDP run
  *before* the tool executes. The model's output is an input to the gate.
- **Default-deny** — anything not explicitly granted is blocked, so obfuscation
  and laundering via *ungranted* binaries fail by construction. This is *proved*
  (`formal.py`): ALLOW ⇒ within-grants, and tightening policy only shrinks the
  allowed set (monotonic confinement).
- **Fail-closed everywhere** — missing/forged policy, unreachable PDP, unknown
  tool, eval error → BLOCK, never silent allow.
- **Integrity** — even if the agent could *write* `policy.json`, it can't
  produce a valid Ed25519 signature, so the PDP rejects it and blocks all
  actions (proven in `signing_test`).
- **Tamper-proof record** — truncating the local audit is detected by the
  external anchor; the off-host mirror survives total local deletion.

## Quickstart — three integration surfaces, one engine

**Claude Code** (`.claude/settings.json`):
```json
{"hooks": {"PreToolUse": [{"matcher": "*",
  "hooks": [{"type": "command", "command": "python -m aegis.hook"}]}]}}
```

**Any platform API** (Anthropic / OpenAI / Bedrock / LangChain) — gate every
tool the model requests before you execute it:
```python
from aegis.guard import Guard
from aegis.model import Effect
guard = Guard.load("aegis/policy.json", audit_path=".aegis/audit.jsonl")
for block in response.content:
    if block.type == "tool_use":
        d = guard.check(block.name, block.input, principal=user_id)
        result = (guard.refusal_text(d) if d.effect is Effect.BLOCK
                  else run_tool(block.name, block.input))
```
(Proven live against a real Haiku call in `live_anthropic.py`.)

**Out-of-process PDP** (the watertight placement — the agent can't tamper):
```bash
aegis-pdp --policy /etc/aegis/policy.json --pubkey <hex> --port 8787
# in the app:  Guard.remote("http://aegis-pdp:8787")   # fails closed if unreachable
```

## Policy is data, owned by the control function

`policy.json` is declarative and version-controlled. Security/compliance tune
grants, allowlists, sensitive terms, prod patterns, big tables, per-pack
effects — no engine change. Sign it before deploy:
```bash
aegis-sign keygen --algo ed25519 --out-dir .
aegis-sign sign --policy policy.json --key signing_key.pem      # -> policy.json.sig
# pin signing_pub.hex in the PDP; mount policy + .sig + pubkey read-only
```

Threat packs (all tunable): `secrets`, `exfiltration`, `pii_egress`,
`destructive_ops`, `prod_protection`, `resource_guard`, `tool_rules`,
`mcp_manifest`, plus opt-in `rbac`, `command_allowlist`, and the
`kdb_code_quality` bridge to an existing engine. Full list in `RULEBOOK.md`.

## Where Aegis sits in the landscape (researched, cited)

The field has independently converged on Aegis's thesis — deterministic,
out-of-process, default-deny, model-independent enforcement (CoSAI/OASIS:
*"never rely on the LLM for security-critical validation"*; classifier-only
guardrails shown evadable up to 100%, arXiv:2504.11168). Aegis is **aligned
with the frontier, and its edge is integration, not any single primitive.**
Production tooling splits into three planes — **no single competitor spans all
of them:**

| Plane | Representative tools | Aegis |
|---|---|---|
| Content / IO filtering | AWS Bedrock Guardrails, Azure Content Safety, Lakera | covered by detector packs (secrets/PII) |
| Tool-call **authorization** | **AWS Cedar / Bedrock AgentCore** (deterministic, formally-verified, GA) | default-deny PDP + `tool_rules` + `mcp_manifest` |
| Data / query plane | **Satori, Immuta** (parse + inject row filters for SQL) | `query_proxy` for **kdb+/q** + SQL |

Honest novelty: the query-proxy *mechanism* (parse-and-inject limits) already
exists for SQL stores (Satori rewrites queries; Immuta uses native DB policies).
Aegis's differentiation is **(1) unifying all three planes + egress + signed
audit + confinement in one default-deny pipeline for the agent, (2) the kdb+/q
target no governance proxy supports, and (3) the financial-services wrapper.**
Where peers lead: AWS Cedar/AgentCore is formally-verified and GA (we have an
exhaustive proof, not yet SMT/Cedar) — adopting Cedar as the policy language is
on the roadmap.

## Compliance posture (primary-source verified)

- **Lead with the EU AI Act** (binding; covers high-risk AI systems). Verified
  verbatim and mapped in `compliance.py`: **Art. 12(1)** automatic event logging
  → tamper-proof audit; **Art. 14(4)** human oversight (override / stop) →
  `require_approval`; **Art. 15** accuracy/robustness/cybersecurity, incl.
  *"resilient against … unauthorised third parties … data/model poisoning,
  adversarial examples"* → red-team corpus + signing + fail-closed.
- **Fed model-risk (SR 11-7) does NOT apply to agents.** Verified from the
  primary source: **SR 26-2 (Apr 2026) supersedes SR 11-7** and states
  generative/agentic AI *"are not within the scope of this guidance."* So Aegis
  is **not** sold as MRM compliance — it is the *"risk management and governance
  practices"* SR 26-2 says should still guide controls for these out-of-scope
  tools.
- `compliance.py` is a **self-verifying** crosswalk: every framework→control
  mapping points at a runnable test and fails if the evidence is missing. It is
  **not legal advice**; verify against primary sources and your control function.

## Deploy

`deploy/` has a hardened `k8s.yaml` (read-only rootfs, non-root, drop ALL caps,
seccomp, deny-egress NetworkPolicy, read-only signed-policy mount), a
`Dockerfile`, and `deployment-profile.json`. Validate before you ship:
```bash
python -m aegis.confinement_test     # checks the profile / a k8s Pod, fail-closed
```

## Coverage & honesty (`redteam_corpus`, `monitor`)

- Red-team corpus: **18/23 caught now, 0 unexpected misses**; 5 cases correctly
  *deferred* to confinement/egress-proxy (documented, not hidden) — proving the
  layered design is necessary.
- Shadow metrics on the labeled corpus: **precision 1.0, recall 1.0,
  FP-rate 0.0** (small benign set — the *methodology* is the deliverable; grow
  the corpus during a monitor-mode rollout).
- AgentDojo: a model-independent defense eval (`agentdojo_eval`, defense/utility
  1.0); the official end-to-end score needs the package + model budget
  (`AGENTDOJO.md`).
- **Per-surface guarantee:** operational agents in containers get *watertight*;
  developer laptops get *strong defense-in-depth* (you can't fully sandbox a
  laptop). Never tell the bank a laptop surface is watertight.

## What Aegis is NOT

It governs agent *actions*. It doesn't make the model truthful, doesn't stop it
*recommending* something bad in text, and doesn't replace the bank's IAM / DLP /
change-control — it composes with them. Claims beyond "mediates and confines
agent actions, fail-closed, fully audited" are overclaims.

## Docs

| File | |
|---|---|
| `THREAT_MODEL.md` | adversaries, trust boundaries, attack classes, the 8 layers |
| `ARCHITECTURE.md` | target design, components, competitive positioning, roadmap |
| `RULEBOOK.md` | every rule / grant, the dos and don'ts |
| `REDTEAM.md` | the evasion corpus, catch-rate, coverage boundary |
| `CONFINEMENT.md` | the L1 controls, what each closes, deploy |
| `AGENTDOJO.md` | how to benchmark against AgentDojo (model-independent + official) |

## Status

Alpha. The full watertight design is implemented and every layer is proven by a
deterministic test (`run_all_checks` → all 15 core green). Remaining: official
AgentDojo live run and a Z3/Cedar lift of the formal proof (budget/effort), plus
P3 niceties (broker SDK, approval-workflow backend, RBAC + cost budgets, WORM
sink adapters).

MIT.
