# Aegis vs the frontier — research synthesis (2026-06-15)

Multi-agent deep-research pass (5 angles, 25 sources, 25 claims adversarially
verified: 23 confirmed / 2 refuted). Verdicts are reasoned judgements on verified
facts, not head-to-head benchmarks. Re-check quarterly — this field moves monthly.

## Top line

The gold standard is converging on exactly Aegis's thesis: **deterministic,
out-of-band enforcement, LLM kept out of the trust loop** — argument-aware
per-tool-call authz (AWS Bedrock AgentCore + Cedar, GA), formal least-privilege
(Progent, PCAS/FORGE, MiniScope), and **information-flow control as the credible
answer to prompt injection** (Microsoft FIDES). Aegis is strongly ALIGNED and in
places AHEAD. Two candid gaps: prompt-injection/tool-output defence (BEHIND), and
a microVM substrate for fully-untrusted code (defensible without, but the frontier).

## Per-layer verdict

| Layer | Verdict | Frontier reference |
|---|---|---|
| Structured-query compiler (data plane) | **AHEAD** (apparently novel) | QUITE rewrites SQL *with* an LLM — opposite trust model; no competitor found compiling agent queries |
| Row-level entitlements | ALIGNED | Satori/Immuta do RLS/masking; none at the q plane |
| Tool-call authorization (grants + Z3) | ALIGNED; Cedar wins on maturity | AgentCore+Cedar (GA), Progent, PCAS, MiniScope |
| Formal-methods assurance (Z3 proofs) | ALIGNED | Cedar Symbolic Compiler (Lean-proven, CVC5) |
| Prompt-injection / tool-output | **BEHIND** | FIDES (IFC labels, stops all AgentDojo injections) |
| OS confinement (ns+Landlock+seccomp) | ALIGNED | SandboxEscapeBench: 0 escape at hardened levels 4-5; microVM = frontier |
| Audit / provenance (WORM) | ALIGNED | NeuroTaint offline provenance auditor (experimental) |

## Prioritised actions (effort -> payoff)

1. **ADOPT — FIDES-style IFC labels (the #1 evolution).** We are BEHIND on
   prompt-injection; FIDES would beat us head-to-head. Tag every content item with
   integrity (trusted/untrusted) + confidentiality labels, propagate through tool
   calls (untrusted-wins), and block a privileged sink *before* it runs — riding
   Aegis's existing chokepoints (PDP veto + structured request). Must preserve
   fail-closed + stdlib-only. Medium-high effort, very high payoff. Closes the gap.
   Refs: FIDES arXiv:2505.23643; devblogs.microsoft.com/agent-framework/fides.
2. **ADOPT — Progent "monotonic confinement" for policy updates.** SMT-classify a
   policy change as narrowing (auto-allow) vs expansion (needs explicit approval),
   so the action space can only shrink without sign-off. Low effort, directly
   strengthens the grants engine. Ref: Progent arXiv:2504.11703.
3. **PARTIAL — deepen Cedar interop for the assurance story.** Don't rebuild on
   Cedar; do run the open-source **Cedar Analysis CLI** (CVC5) on our exported
   policies for independent, third-party-recognisable corroboration alongside our
   Z3 proofs. Medium effort, high audit/MRM payoff. Refs: arXiv:2407.01688; AWS
   Cedar Analysis blog (Jun 2025).
4. **MONITOR/PARTIAL — NeuroTaint-style offline provenance auditor** over the
   hash-chained WORM trace (audit plane, NOT enforcement). Enriches the MRM story.
   Lower urgency than runtime IFC. Ref: arXiv:2604.23374 (preprint, single-source).
5. **MONITOR — microVM substrate (Firecracker/Kata).** SandboxEscapeBench shows
   namespaces+Landlock+seccomp plausibly lands at the "zero escape at levels 4-5"
   tier vs current models, so it's defensible for first-party agents. Adopt a
   microVM only if the threat model includes untrusted *third-party* agent code.
   High effort. Ref: SandboxEscapeBench arXiv:2603.02277 (preprint).
6. **KEEP/PROMOTE — the structured-query compiler.** AHEAD and apparently novel;
   lead with it in MRM reviews. Zero effort, high credibility payoff.

## Honest flags (do NOT overclaim)

- **Two refuted claims — must not be cited:** (1) PCAS/FORGE does NOT have an
  established formal soundness guarantee comparable to our Z3 proofs (0-3). (2) The
  spotlighting ">50% to <2%" efficacy figure failed verification (0-3) — spotlighting
  is only a probabilistic prompt-engineering mitigation.
- **Compiler novelty is inferential** — no competitor found in the surveyed corpus,
  not an exhaustive proof. Needs a targeted Satori/Immuta/KX-vendor sweep before
  claiming "first-of-kind" externally.
- **Several arXiv IDs are future-dated 2026** (PCAS 2602.x, NeuroTaint 2604.x,
  SandboxEscapeBench 2603.x) — treat as preprints. FIDES (2505.x) and AgentCore/Cedar
  are solid/shipped.
- **Verdicts are reasoned, not benchmarked.** Only an actual bake-off (AgentDojo,
  SandboxEscapeBench) would settle behind/aligned/ahead empirically.
- **Priority F (standards/regulatory mandatory controls) was NOT resolved** by the
  surviving claims — OWASP Agentic Top 10 (2026), NIST agent guidance, EU AI Act
  timeline, FS-ISAC bank guidance need a dedicated pass to find mandatory controls
  we lack.

## Open questions to close next

- Targeted Satori / Immuta / KX sweep to confirm or retire the compiler-novelty claim.
- Concrete integration cost + false-positive/usability impact of FIDES-style IFC on
  our chokepoints, preserving fail-closed + stdlib-only.
- Dedicated standards/regulatory pass (Priority F) for mandatory-control gaps.
