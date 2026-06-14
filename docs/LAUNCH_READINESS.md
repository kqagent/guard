# Aegis — launch readiness (tie-it-together plan)

*2026-06-14. What's done, what remains, and the honest gate to calling Aegis a
launchable product rather than a strong pilot. Read with `pilot/ASSESSMENT.md`
(the enforce-readiness scorecard) and `docs/CONTROL_FUNCTION_BRIEF.md`.*

## Where we are

Engineering-complete and internally **GO for enforce on the structured kdb+
analyst surface**. 25/25 acceptance batteries, CI-gated (suite + ruff +
confinement + Landlock on a native-Linux runner). Proven on a live 4-stack FSP
estate: 52/52 benign served, 0/50 targeted-attack-success measured at the gate,
kernel confinement 7/7 + 6/6, signed out-of-process PDP + off-host WORM audit.

The query plane is bounded-by-construction (structured compiler, two injection
red-teams 11/11 and 12/12 plus a 9/9 join red-team); confinement is the
load-bearing control; the deterministic supervisor + kill switch are wired and
exercised.

## The launch gates — what "launchable product" actually requires

### A. Human gates (cannot be closed by us — these define launch)
1. **Real-data re-soak by the control function.** FP/attack numbers are on a
   representative corpus + sample schema; re-measure on the real desk corpus and
   real data. This is the named go-live condition in the scorecard.
2. **Third-party security audit.** Before a production trading estate depends on
   it, an external review of the compiler (primary control), the confinement, and
   the signed-policy/PDP path. Self-verification is not independent verification.
3. **Design-partner production run** in monitor mode → the first real
   false-positive number on production traffic, and the reference customer.

### B. Engineering items to finish before GA (we can close these)
1. **Re-wire the LLM overseer into the live loop.** `aegis/overseer.py` (the
   second-line "LLM watches the audit") is built, tested, and live-proven, but
   was left unwired during the structured-API pivot — no policy enables it, the
   PDP doesn't invoke it, no soak used it. Wire it so an incident gets an
   overseer narrative + advisory escalation (advisory only — it never gates;
   deterministic supervisor stays load-bearing). Today the two-tier-oversight
   story is half-deployed; close that before claiming it.
2. **Window-join grammar slot** (1/52 uncovered) — add as a reviewed structured
   op if the desk needs it; otherwise document the boundary.
3. **Break-glass surface hardening** — the free-form `run_query` path (admin-only)
   still rests on a deny-list over q + confinement. Either keep it strictly
   break-glass (separately signed, audited, never analyst-granted) or invest in a
   completeness story. Decide and document; don't let it drift toward analysts.
4. **Control-function policy authoring kit** — make it turnkey for a bank to
   author + sign `policy.kdb.json` (real tables/columns/sensitive terms) and
   validate the manifest (`verify_deployment.py`), without engineering. Today it's
   doable but expert-only.
5. **Packaging for a clean install** — PyPI release, pinned deps, the
   quickstart/Docker/k8s paths smoke-tested on a fresh box by someone who isn't us.

### C. Positioning / GTM (non-code, but gates a confident launch)
1. **Define what "launch" means** — design-partner pilot vs general availability.
   Recommend: launch = *named design partner running enforce on one desk*, GA only
   after A2/A3. Don't market GA off a self-run pilot.
2. **The honest one-liner** — "a bounded-by-construction query guardrail for LLM
   agents on kdb+ estates, with kernel confinement as the load-bearing control."
   Lead with the kdb+ depth (the genuine differentiator) and the structural-
   impossibility design; never imply the gate alone is containment.
3. **Frontier framing** — aligned with the frontier (Cedar/AgentCore on authz,
   the namespace/Landlock sandbox class), differentiated on the unified kdb+ query
   plane + fail-closed posture. (`docs/Frontier-Assessment-2026-06.md`.)

## Recommended sequence to launch

1. **Now:** finish B1 (re-wire overseer) + B5 (packaging) — the two that make the
   product *whole* and installable. (Engineering, ~days.)
2. **Then:** put `CONTROL_FUNCTION_BRIEF.md` + the scorecard in front of the
   control function; line up A1 (real-data re-soak) and A3 (design partner).
3. **Before GA:** A2 (third-party audit); B3/B4 decisions documented.

## Honest bottom line

The hard technical problem — letting an LLM work *around* a prod kdb+ estate
without being able to harm it — is solved on the analyst surface, and solved the
right way (structural impossibility + kernel containment, not pattern-policing).
What stands between "strong pilot" and "confident product launch" is now mostly
**not code**: a real-data re-soak, an external audit, a design partner, plus two
finishing engineering items (overseer re-wire, packaging). That is a credible,
nameable path — and a good place to be.
