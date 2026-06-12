# Aegis — deterministic, fail-closed policy gate for LLM agents

Standalone repo extracted from the kqScrape monorepo on 2026-06-12.
Package layout: `aegis/` is the package, pyproject at root.

## Commands

```bash
.venv/Scripts/python.exe -m aegis.run_all_checks   # acceptance suite — must stay ALL CORE PASS
.venv/Scripts/python.exe -m aegis.demo             # quick PoC demo (engine + fail-closed + audit tamper)
```

Each battery is also runnable standalone: `python -m aegis.<name>` for
demo, example_api_loop, proxy, pdp_test, query_proxy_test, egress_proxy_test,
signing_test, confinement_test, audit_worm_test, monitor, formal,
agentdojo_eval, compliance, mcp_test, redteam_corpus, worm_sinks_test,
approvals_test, budget_test, sdk_test, cedar_export.

OPTIONAL tier: `verify_kdb_bridge` (needs `tools/gate.js` from the old
kqScrape repo — not in this repo) and `formal_smt` (Z3 proofs over unbounded
domains; needs the `[formal]` extra, installed in this venv).

The official AgentDojo run: `python tools/run_agentdojo_official.py --dry-run`
works keyless; the live score needs ANTHROPIC_API_KEY (see aegis/AGENTDOJO.md).

## Hard constraints

- **The enforcement path is stdlib-only — zero third-party deps.** The gate
  must never fail OPEN because an import failed. `cryptography` is an
  optional extra for Ed25519 signing only (HMAC fallback is stdlib).
- **Fail-closed everywhere.** Policy load error, PDP unreachable, missing
  signature → block, never allow.
- **Enumerate goodness, not badness.** Default-deny via `grants` in
  policy.json; detectors are a veto on granted actions, not the primary gate.
- Don't weaken a red-team corpus case to make it pass — `redteam_corpus.py`
  fails only on unexpected misses; deferred-to-confinement cases are
  documented honestly in REDTEAM.md.

## Where things are

- Design docs: `aegis/ARCHITECTURE.md`, `aegis/THREAT_MODEL.md` (adversarial,
  honest about detector bypassability), `aegis/RULEBOOK.md` (threat packs),
  `aegis/CONFINEMENT.md`, `aegis/REDTEAM.md`, `aegis/AGENTDOJO.md`
- Policy: `aegis/policy.json` (control-function-authored, signable)
- Deployment hardening references: `aegis/deploy/` (k8s.yaml, Dockerfile,
  deployment-profile.json)
- Sales/exec material: `docs/Aegis-Executive-Summary.md` (+ PDF), rebuilt via
  `tools/build_aegis_brief.py`
