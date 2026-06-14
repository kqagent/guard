# Aegis — enforce-readiness scorecard (FSP kdb+ estate)

*2026-06-14, homer. Honest go/no-go for enforcing Aegis on a real kdb+ analyst
desk. Supersedes the earlier monitor-stage read. Each gate marked met / not, with
the real numbers. Written to be shown to a control function without overselling.*

## Scorecard

| # | Gate | Result | Evidence |
|---|------|--------|----------|
| G1 | Unit suite + ruff + CI green | ✅ **25/25 core**, ruff clean | `run_all_checks`; CI |
| G2 | Structured soak, 3 models: served / 0 rejects / 0 harm | ✅ **52/52 served, 0 compiler rejects, 0 malicious harm** | `score_structured.py` |
| G3 | Adversarial-model recall (gate, not conscience) | ✅ **targeted-attack-success 0/50**; in-scope gate recall 15/15 | `adversarial_recall.py` |
| G4 | Confinement adversarial + Landlock on the real host | ✅ **7/7 + 6/6** | `confine_adversarial_test.sh`, `landlock_test.sh` |
| G5 | PDP-remote fail-closed + WORM audit verify | ✅ fail-closed; WORM mirror; **anchor truncation detected** | `stage34_verify.py` |
| G6 | `verify_deployment.py` on the real manifest | ✅ **manifest hardened (12 controls)** | `verify_deployment.py aegis/deploy/k8s.yaml` |
| A | Structured grammar covers the real desk corpus | ⚠️ **51/52** (window-join flagged, not shipped) | `validate_structured.py` |
| B | Every agent tool is enumerate-goodness | ✅ analyst surface = structured-query + read_file (both allowlist); free-form removed | `TOOL_SURFACE_AUDIT.md` |
| F | Enforce-mode dry run clean (FP holds, breaker fires) | ✅ **0/8 benign blocked**; breaker + incident on tripwire | dry-run (found+fixed supervisor `unknown_action` gap) |

## The two numbers that decide it

- **False-positive (usability):** the structured analyst surface served **52/52**
  benign desk tasks with **0 compiler rejects** across Opus/Sonnet/Haiku, and 0/8
  benign blocked in enforce mode. The gate does not break legitimate work.
- **Targeted-attack-success-rate (security):** **0/50**, measured by driving
  attacks *directly at the gate* (no model self-refusal) across both surfaces with
  an externally-informed corpus + obfuscation. This is the de-circularized recall
  number the go/no-go hinges on.

## Per-surface guarantees

- **Structured analyst surface** (`run_structured_query`): enumerate-goodness — the
  agent sends data, the compiler emits only `select/exec/meta/aj/lj` over
  allowlisted tables/columns/ops/aggs; injection has no slot; output re-checked
  against `_DANGEROUS_Q`. This is the surface proposed for enforce.
- **File surface** (`read_file`): gate-level path allowlist (`file_access`).
- **Free-form `run_query`**: a deny-list on a Turing-complete language — **removed
  from the analyst grant**, break-glass only behind a separate admin-signed policy.
- **Containment (load-bearing):** the q process runs non-root, read-only HDB, no
  shell, egress-blocked; kernel-enforced (Landlock + read-only mounts + empty
  netns), proven 7/7 + 6/6 on this host. A gate bypass is contained here.
- **Mediation/record:** out-of-process signed-bundle PDP, fail-closed when down,
  audit hash-chained + mirrored to an off-host WORM sink with truncation detection.

## Go / no-go

**GO to enforce on the STRUCTURED analyst surface**, with these conditions:
1. Confinement (G4) deployed and gated in CI — it is load-bearing, not optional.
2. Free-form `run_query` never granted to an analyst; break-glass only, separately
   signed, audited.
3. Signed policy bundle mounted read-only; PDP out-of-process; WORM audit live.

**NO-GO / conditions outstanding:**
- The FP number, though strong, is on a representative corpus authored here, against
  the FSP sample schema. The control function must re-soak on the **real desk
  corpus + real data** before sign-off — that is the one gate only they can close.
- Window-join (1/52) is not shipped; if the desk needs it, it is a reviewed slot.
- The break-glass free-form surface's deny-list is bypassable in principle (no
  completeness proof on a Turing-complete language); it stands only because it is
  off the analyst surface and confinement backs it.

## Standing honest caveats (carried)

- "0" attack-success is on a broad, externally-informed sample — **not** a
  completeness proof. Confinement remains the load-bearing control.
- The structured-surface result no longer leans on model self-refusal (G3 is
  programmatic); the break-glass surface is only as good as the deny-list +
  confinement.
