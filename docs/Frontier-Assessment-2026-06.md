# Aegis vs the frontier — assessment (June 2026)

Deep-research pass (23 sources, 108 extracted claims; 7 confirmed 3-0 by
adversarial verification, 18 sourced-but-unverified after the verifier hit a
rate limit — those are from primary arXiv/AWS/OWASP/BPI sources and are
treated here as "likely, pending re-verify"). Verdict per layer, then the
highest-leverage evolutions.

## Headline

The frontier independently converged on Aegis's thesis: **deterministic,
out-of-process, default-deny, fail-closed enforcement — not in-prompt
instructions or LLM classifiers.** On the most important layer (OS
sandboxing) we are *aligned with the frontier, not behind it* — and on one
axis (fail-closed) we are ahead of Anthropic's own shipped sandbox. The work
to do is targeted, not a redesign.

---

## Layer-by-layer

### 1. OS sandboxing — ALIGNED (with one honest gap and one edge) — CONFIRMED 3-0
The frontier coding agents isolate untrusted agent code with **unprivileged
Linux kernel primitives**, exactly our class — not microVMs:

- **Claude Code** (Anthropic, primary source, confirmed): Linux/WSL2 sandbox =
  **bubblewrap (unprivileged user namespaces) + socat + optional seccomp**. Not
  Firecracker, not gVisor, not Kata. Documented as "not a complete isolation
  boundary." **And it FAILS OPEN by default** — if the sandbox can't start it
  runs the command *unsandboxed* unless `failIfUnavailable=true`.
- **OpenAI Codex** (sourced): Bubblewrap primary + **Landlock** fallback;
  `--unshare-user/--unshare-pid/--unshare-net`; read-only-by-default fs with
  `--bind` writable roots. Same primitives we use.
- **Sandlock** (arXiv 2605.26298, confirmed): Landlock + seccomp-bpf + seccomp
  user-notification, ~5 ms startup; explicitly concedes that **for multi-tenant
  adversarial workloads "a microVM remains the right answer,"** and puts kernel
  vulns / side channels / privileged-local-attacker / resource-exhaustion
  out of scope.

**Verdict:** our user/mount/net/pid-namespace + pivot_root + RO-mount + rlimits
+ no-new-privs design is the de-facto standard for this use case. **Edge:**
Aegis is fail-closed throughout; Claude Code's sandbox is fail-open by default —
a genuine, citable differentiator for a bank. **Honest gap:** raw-namespace
confinement is materially weaker than a microVM against a kernel-level attacker;
say so the way Sandlock does, and offer a microVM substrate as an option.

### 2. Tool-call authorization — ALIGNED
- **AWS Bedrock AgentCore Policy + Cedar** (confirmed 2-0): Cedar, **default-deny
  at the Gateway PEP**, evaluates each MCP tool invocation *with arguments* —
  structurally identical to our PDP + grant algebra + tool-arg rules. GA, vendor-
  supported, formally-analyzable policy language.
- **Progent** (arXiv 2504.11703, sourced): symbolic rules over tool+args, **SMT
  decides narrowing vs expansion → monotonic confinement** — the same property
  our `formal_smt.py` proves, but they generate/update policy with an LLM at
  runtime.
- **PCAS** (arXiv 2602.16708): Datalog reference monitor over a *causal
  dependency graph* with transitive information-flow — richer than our flat
  grants.
- **AgentBound** (arXiv 2510.21236): Android-style per-server permissions; **can
  auto-generate policy from MCP server source at 80.9% accuracy** — a capability
  we don't have.

**Verdict:** aligned; Cedar is the incumbent we should interoperate with (we
already export to it). Progent's runtime-policy-synthesis and AgentBound's
auto-authoring are the ideas worth borrowing.

### 3. Query plane — NOT mechanism-novel, but kdb+ is ours
The ICSE'25 prompt-to-SQL paper (syssec.dpss.inesc-id.pt) already publishes
**query rewriting** (authorization-scoped nested subquery) and a **parser that
permits only SELECT / blocks mutations** as "complete solutions" for read-attack
classes — the same parse-then-rewrite-or-reject design as our proxy. Object-
capability SQL sandboxing (ryanrasti) is another entrant.

**Verdict:** stop claiming query-plane rewriting is novel. **The defensible
claim is the kdb+/q target** (no published competitor does q's functional form,
date-partition injection, `select[n]` caps) **plus coupling the query plane into
a unified agent-guardrail pipeline.**

### 4. Prompt-injection defense — our thesis is validated; a layer to add
The ICSE paper found **all 5 real LangChain/LlamaIndex apps and all 7 LLMs
vulnerable** to prompt-injection; prompt-hardening is fragile. This is the
empirical backing for "only deterministic out-of-band enforcement is
load-bearing" — our whole premise.
**Evolution:** **CaMeL** (arXiv 2503.18813) — capability + control/data-flow
extraction so untrusted data can't influence control flow — is the design to
study for a future taint-tracking layer. We don't need to be CaMeL, but our
detector packs are the weakest, most-bypassable layer and a dataflow approach
would harden the tool-output path.

### 5. Audit / kill-switch / oversight — ALIGNED, and bank-validated
- Bank trades (**BPI + ABA**, primary) asked NIST for exactly: "investigation-
  ready records and traceability" (→ our WORM audit), **"safeguards for higher-
  risk actions, shutdown and revocation support"** (→ our approval workflow +
  the **circuit-breaker kill switch** just shipped), and "secure machine-to-
  machine access and authentication" (→ grants + PDP).
- The **FSB** is pointing banks toward **"AI monitoring AI" as human oversight
  reaches its limits** — direct validation of the **LLM overseer** layer.
- **OWASP Top 10 for Agentic Applications 2026** now exists as a standalone
  taxonomy; our compliance crosswalk should cite it explicitly.

**Verdict:** the kill-switch + WORM + overseer map onto *named* bank-requested
controls. This is our strongest positioning evidence.

---

## Highest-leverage evolutions (ranked)

1. **[DONE 2026-06-14] Landlock LSM filesystem confinement.**
   `aegis/deploy/landlock_confine.py` — kernel-enforced, unprivileged, no mounts
   (works where sub-path RO binds don't, e.g. WSL2; identical in prod). Proven
   `landlock_test.sh` 6/6 + in CI on a native-Linux runner: out-of-allowlist
   secrets unreadable, system dirs read-only, no-new-privs set. Matches Codex/
   Sandlock. **Still open:** seccomp-bpf syscall filtering (cuts kernel attack
   surface further) — next confinement increment.
2. **[DONE 2026-06-14] microVM substrate option documented** — `deploy/MICROVM.md`
   (Kata drop-in via runtimeClassName; Firecracker standalone with vsock to the
   PDP). Threat model stated honestly per Sandlock (kernel vulns / side channels
   out of scope for the namespace/Landlock default; microVM is the upgrade for
   adversarial multi-tenant). We do not claim namespace == microVM.
3. **Keep fail-closed front-and-centre** — it's a real edge over Claude Code's
   default-fail-open sandbox. Make sure our confinement runner also fails closed
   (refuses to run the payload if a namespace/Landlock step fails).
4. **Borrow from the authz frontier:** AgentBound-style policy auto-generation
   from tool definitions; Progent-style runtime narrowing with our existing Z3.
5. **Study CaMeL** for a future dataflow/taint layer on tool outputs — the one
   place our design is weakest (regex detectors).
6. **Cite OWASP Agentic Top-10 2026 + the BPI/ABA + FSB language** in the
   compliance crosswalk and sales material — named requirements we already meet.

## Where we'd lose a bake-off (be honest)
- **vs AWS AgentCore + Cedar** on the *general* tool-authz plane: they're GA,
  vendor-supported, formally-analyzable, cloud-native. We win only on multi-
  plane unification + kdb+ + cloud-neutral + fail-closed. Don't fight them on
  their turf; interoperate (Cedar export) and differentiate on ours.
- **vs a microVM platform (E2B/Modal/Firecracker)** on hard adversarial
  isolation: a determined kernel-level attacker is in-scope for them, out-of-
  scope for our namespace sandbox. Mitigate by offering the microVM option.

## Sources (primary, confirmed unless noted)
- Claude Code sandboxing — code.claude.com/docs/en/sandboxing (confirmed 3-0)
- Sandlock — arxiv.org/html/2605.26298v1 (confirmed 3-0)
- AWS AgentCore + Cedar — aws.amazon.com/blogs/security/... (confirmed 2-0)
- OpenAI Codex sandbox — deepwiki.com/openai/codex/5.6 (sourced)
- Progent 2504.11703, PCAS 2602.16708, AgentBound 2510.21236, CaMeL 2503.18813 (sourced)
- Prompt-to-SQL ICSE'25 — syssec.dpss.inesc-id.pt/papers/pedro_icse25.pdf (sourced)
- OWASP Agentic Top 10 2026 — genai.owasp.org (sourced)
- BPI/ABA NIST comment — bpi.com/bank-trades-comment-on-nists-... (sourced)
- FSB AI oversight — theasianbanker.com/... (sourced)
