# Aegis pilot readiness — from PoC to enforcing on a non-prod kdb+

*2026-06-12. How to take Aegis from "20/20 batteries green" to "enforcing on
a real kdb+ analyst agent," without a big-bang cutover. The governing
principle is the one the product was built on: **monitor first, measure the
false-positive rate on real traffic, then enforce.** Nothing blocks a real
user until the FP rate is known and accepted.*

## Where it stands today

| | Status | Evidence |
|---|---|---|
| Deterministic core + all layers | **proven** | `python -m aegis.run_all_checks` → 20/20 core |
| Grant algebra, unbounded | **proven** | `python -m aegis.formal_smt` → 24 Z3 theorems |
| Reference deployment hardened | **proven** | `python tools/verify_deployment.py` → 12/12 controls |
| Signed bundle build + tamper-reject | **proven** | `python aegis/deploy/build_bundle.py ./bundle` |
| Gate + query proxy on a kdb agent | **wired, shadow-proven** | `python -m aegis.live_kdb_agent --dry-run` |
| Query rewrites vs **real q** | **harness ready, blocked** | `tools/validate_query_proxy_q.py` (needs valid `kc.lic`) |
| Official AgentDojo score | **harness ready, blocked** | `tools/run_agentdojo_official.py` (needs `ANTHROPIC_API_KEY`) |
| Live agent soak | **not started** | needs key + licence + a real task set |

Two external blockers, both outside the code: a **valid kdb+ licence**
(the local `kc.lic` is expired) and an **Anthropic API key**. Every harness
that needs them detects their absence and skips cleanly with a ready-to-run
message — none are code gaps.

## The staged path

### Stage 0 — unblock the environment (owner: you)
- [ ] Install a valid `kc.lic` (set `QHOME`/`QLIC`). Verify: `tools/validate_query_proxy_q.py` runs instead of skipping.
- [ ] Provide `ANTHROPIC_API_KEY` (env var, never on disk). **Rotate the key pasted in chat 2026-06-04 if not already done.**
- [ ] Pick the pilot surface: which agent, which kdb tables, which analysts.

### Stage 1 — author YOUR policy (owner: control function / 2nd line)
The shipped `policy.kdb.json` is a template. Replace its defaults with real
values; this is the control function's artifact, not engineering's.
- [ ] `grants.tools` — the actual named tools your agent exposes.
- [ ] `query_proxy.allowed_tables` / `require_date_tables` — your real schema.
- [ ] `pii_egress.sensitive_terms` — your classified-data vocabulary.
- [ ] `prod.patterns`, `egress.allowlist_hosts` — your prod markers and approved hosts.
- [ ] Sign it: `python aegis/deploy/build_bundle.py ./bundle` → store the private key in HSM/KMS, delete from disk.
- [ ] Optionally export to Cedar for review: `python -m aegis.cedar_export`.

### Stage 2 — shadow / monitor mode (owner: platform + control function)
- [ ] Run the agent against a **non-prod kdb** with `mode: "monitor"` (default in `live_kdb_agent`; do NOT pass `--enforce`).
- [ ] Drive it with a representative task set (real analyst questions, not synthetic).
- [ ] Collect `.aegis/shadow-decisions.jsonl` over enough traffic to be meaningful.
- [ ] Score it: `python -m aegis.monitor` against a labelled slice — **acceptance gate: FP-rate = 0 (or an explicitly accepted budget) and recall = 1 on the in-scope malicious set.**
- [ ] Tune `policy.kdb.json` from the false positives; re-run. Iterate until the gate is quiet on legitimate work.

### Stage 3 — validate the query plane against real q (owner: platform)
- [ ] `python tools/validate_query_proxy_q.py` — confirm every rewrite parses and runs in YOUR q build and is genuinely bounded.
- [ ] Spot-check the rewrites a real analyst would notice (does the injected `where date=.z.d` match their partitioning? is the row cap sane for their tables?).

### Stage 4 — deploy the enforcement plane (owner: platform/SRE)
- [ ] Stand up the **out-of-process PDP** (`aegis-pdp`) with the signed bundle mounted read-only and `--pubkey` pinned.
- [ ] Apply the hardened manifest; **gate the deploy in CI**: `python tools/verify_deployment.py <your-manifest>` must pass 12/12.
- [ ] Point the audit at a real **WORM sink** (syslog collector / S3 Object-Lock / HTTP append API — adapters in `aegis/worm_sinks.py`); for regulated surfaces set `strict_sinks=True`.
- [ ] Wire the **approval backend** (`aegis-approve` CLI or an ITSM adapter) for `require_approval` decisions.
- [ ] Build the **egress-proxy serving daemon** (currently `EgressGuard` is a library; the forward-proxy shim is the one remaining P3 code item — until then the agent enforces egress in-process and the network is `internal: true`).

### Stage 5 — flip to enforce (owner: control function sign-off)
- [ ] Only after Stage 2's FP gate is met and Stages 3–4 are green.
- [ ] Flip `mode` to `enforce` (or run `live_kdb_agent --enforce`). Blocked calls now return the refusal to the model; `require_approval` routes to the broker.
- [ ] Keep the monitor metrics running — a rising FP rate after a policy change is the signal to roll back.

## Acceptance gates (must all hold before enforce)
1. `run_all_checks` 20/20 and `formal_smt` green on the deployed commit.
2. `verify_deployment.py` 12/12 on the actual manifest.
3. Signed bundle verifies and a tampered policy fails closed (build_bundle self-test).
4. Shadow FP-rate within accepted budget, recall = 1 on the in-scope malicious set.
5. `validate_query_proxy_q.py` green against the production q build.
6. WORM sink delivering; audit chain verifies (`audit.verify` / `verify_against_anchor`).

## Honest residual risk (carried from THREAT_MODEL.md)
- Pattern detectors are bypassable; **confinement is load-bearing**, the gate is defense-in-depth. Stage 4 hardening is not optional.
- The compliance crosswalk text is paraphrased, not legally verified — 2nd-line/legal must review before it's cited to a regulator.
- The official AgentDojo attack-success number is still pending a funded live run.
