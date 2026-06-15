# Handoff: build the three research-adopt features on the estate

**Branch:** `pilot/row-entitlements` (IFC layer + research report already landed)
**Source:** `docs/Aegis-Frontier-Research-2026-06.md` — these are the buildable
items from the prioritised adopt list. All three are yours to build + validate;
the laptop is staying out of the dev so the work happens where the harness, the
`agentdojo` package, and the funded model run live. Suite must stay green
(currently 31/31 core); add each new test to `run_all_checks`.

---

## Feature 1 — AgentDojo IFC integration + the OFFICIAL run (highest priority)

This is the external benchmark that's still outstanding — the recognised number
an auditor/MRM review wants, and the head-to-head vs FIDES/Progent (0% attack
success). Two parts:

**1a. Wire IFC into the AgentDojo pipeline.** `tools/run_agentdojo_official.py`
already has an `AegisGatedExecutor` that runs the engine detectors before each
tool call but it predates IFC. Extend it so the IFC veto runs too:
- Keep a `Provenance` ledger (`aegis.ifc`) per task run.
- As each tool RESULT returns, tag it: an external/injected tool output is
  UNTRUSTED; results carrying pii terms (positions/pnl/account_no/iban) are
  SENSITIVE; the user's own task prompt is TRUSTED.
- Author the per-suite `SinkPolicy` (privileged_tools = send_money,
  send_email, post_webpage, delete_file, update_password, etc.; egress_tools =
  the send/post tools).
- Before executing a model-requested call, `Provenance.guard(tool, from_items)`
  where `from_items` names the results that fed the call; compose the IFC Finding
  with the detector Decision (most-severe wins). A blocked call returns the
  refusal as the tool error, exactly as the executor does now.

**1b. Mirror it in the model-independent eval.** Extend `AegisToolFilter` in
`aegis/agentdojo_eval.py` with an optional `ifc_policy`, an `observe(item,label)`
method, and a `from_items` arg on `allow()`; add an INDIRECT-injection section to
`run()` (a tainted tool output then a privileged call derived from it must be
blocked — include a tool with NO detector rule, e.g. `submit_order`, to show IFC
adds coverage the detectors miss; a trusted-derived call stays allowed). Keep the
existing direct defense/utility at 1.00.

**Run + report.** `--dry-run` first (wiring), then the funded run (start
`--suites banking --tasks 3` to size cost). Report benign utility,
utility-under-attack, and targeted-attack-success WITH IFC vs WITHOUT, per suite.
Target: attack-success at/near 0 while benign utility holds.

## Feature 2 — Progent "monotonic confinement" for policy updates

A guard on policy CHANGES: a new policy may only ever SHRINK the allow-set without
explicit approval. Given (old_policy, new_policy):
- classify the diff as NARROWING (every action the new policy allows was already
  allowed) -> auto-apply; or WIDENING (the new policy allows some action the old
  did not) -> require explicit approval, and report exactly which actions are
  newly allowed.
- Reuse the grant algebra in `aegis/formal.py` (it already proves monotonic
  confinement by exhaustion over the modeled action universe; lift that into a
  diff over two policies). The Z3 path can prove it over unbounded domains.
- Test: narrowing auto-allowed; widening flagged with the specific new grants;
  identity = no change; fail-closed if either policy won't load.
- Wire it into the policy-load/sign path so an unreviewed widening can't ship.

## Feature 3 — Cedar Analysis CLI runner

Independent corroboration of our Z3 grant-algebra proofs using AWS's open-source
**Cedar Analysis CLI** (CVC5-backed, Lean-proven), for the assurance story:
- A runner that takes the policies emitted by `aegis/cedar_export.py`, feeds them
  to the Cedar Analysis CLI, and reports the validation / policy-equivalence
  result alongside our own proof.
- The actual run needs the Cedar Analysis tool installed (Rust toolchain) — build
  the runner + docs and flag the dependency; gate it OPTIONAL-tier (skip cleanly
  when the tool is absent, like `q_conformance_test`), so CI without Cedar stays
  green. Do NOT rebuild Aegis on Cedar — this is corroboration only.

---

**Report back per feature:** the AgentDojo official numbers (the big one), the
monotonic-confinement classifier behaviour on a real narrowing + a real widening
of the production policy, and the Cedar Analysis result (or the documented
skip if the tool isn't installed). Suite green throughout.

Honest-scope reminders from the research: don't cite PCAS as formally verified
(refuted) or spotlighting's efficacy numbers (refuted); the compiler-novelty
claim is still inferential pending a Satori/Immuta/KX sweep (separate task).
