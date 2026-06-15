# Handoff: validate the compiler/confinement hardening on the real 4B-row estate

**Branch:** `pilot/row-entitlements` (code through `a68e3b7`; this brief `7c81731`)
**Who:** you have the real partitioned kdb+ estate (4B rows, real desk corpus, the
uncooperative jailbroken-Opus attacker harness). I (laptop) wrote and unit/real-q
verified everything below on a tiny fixture HDB + WSL kdb+; what I cannot do is
prove it at scale or against the real schema and real principals. That is the
gate only you can close.

**What changed since your "28/28, branch up for review" delivery.** I reviewed
that branch, found two entitlement holes your delivery proof did not cover (see
§1), fixed them, and built the three follow-ups you flagged as out-of-scope
(q-conformance battery §2, schema-diff linter §3, seccomp §4). Suite is now
**30/30 core**. The load-bearing properties you proved (mandatory
AND-intersection vs an agent filter, injection-safe values, principal from PDP)
still hold — this brief asks you to extend the proof to the cases they didn't.

Pull the branch and run the suite first:

```bash
git fetch && git checkout pilot/row-entitlements && git pull
python -m aegis.run_all_checks         # expect: ALL CORE PASS 30/30
```

On your native-Linux box the OPTIONAL tier should now actually run:
`q_conformance_test` (needs q — set `AEGIS_Q_BIN`/`AEGIS_QHOME` to the estate's q)
and `seccomp_test`'s kernel half. Report the full output.

---

## 1. Entitlement combine-semantics change — THE blocker for merge to main

Two holes your delivery proof did not exercise, both now fixed in
`_entitlement_preds`/`_entitlement_gate`:

**(a) `*`-baseline-vs-table-rule WIDENING.** Your proof showed an agent asking
for a non-entitled symbol gets the intersection (empty) — correct, and still
true. But that is the *agent-filter* path. The hole was a *cross-rule* path: a
principal with BOTH a `*` baseline (e.g. `region in EMEA`) AND a table-specific
rule (e.g. `trade -> sym in AAPL MSFT`). The table rule was **replacing** the
`*` baseline, so the compiled trade query carried only `sym in AAPL MSFT` — the
`region in EMEA` fence silently dropped. Fix: both are now ANDed (narrowest,
fail-safe).

> Re-prove THIS case, not the agent-filter case you already passed. Configure a
> principal with a `*` fence + a table-specific filter, compile a query for the
> table that has the specific rule, and confirm the emitted q carries BOTH
> predicates and the rows returned satisfy BOTH. The old test (agent asks for a
> symbol outside its set -> 0 rows) does NOT cover this and will look green
> either way.

**(b) `meta` bypassed default-deny.** `op:'meta'` returned `meta <table>` before
any entitlement check, so an un-entitled principal could enumerate a table's
schema. Fix: `meta` is now gated. Confirm `op:'meta'` by an un-entitled
principal is REJECTED.

**Then the regression sweep (the change is stricter -> can over-restrict):**
- For every pilot principal, run their representative queries through the gate
  and confirm rows returned equal their intended entitled set — no principal now
  **over-restricted** (missing rows they should see) nor **under-restricted**.
  Diff against the pre-change behaviour if you still have it.

If any pilot principal narrows unexpectedly, that is a policy-authoring decision,
not a bug — flag it so the control function re-confirms the intended set before
we merge. **Do not merge to main until the combine case is signed off on real
data.**

## 2. q-semantics conformance battery — reconfirm at scale

`aegis/q_conformance_test.py` proves the compiler's safety bounds on real q, but
on a tiny fixture (N=5000, cap=1000). The original two regressions
(aggregation-corruption; materialisation) were only visible at 500M scale.

- Run the battery as-is on the estate's q (it builds its own fixture) — should
  be green; confirm the `.Q.dpft` enumerated-symbol handling matches your sym
  file setup.
- Then **re-prove P1/P2 at real scale**: on a real 4B partition, compile a raw
  listing and confirm the emitted `i<N` bounds materialisation (watch RSS), and
  compile `count`/`sum`/`avg`/`count by sym` and confirm they equal an
  independent uncapped query (NOT the cap). This is the regression backstop —
  earn it on real partitions, not the fixture.
- Note: q `sum` over int64 wraps silently (battery P7, informational). Check
  whether any real desk aggregation (`sum size` volume, notional) over a wide
  range can actually overflow on this estate; if so we should decide on widening.

## 3. Schema-drift linter — run against the real schema

```bash
python -m aegis.policy_schema_diff --policy pilot/realism/policy.realism.json --hdb <real HDB path>
```
Triage every finding: `TABLE-MISSING`/`COL-MISSING`/`ENT-COL-*` are real drift
to fix; `NEW-COL` and `PART-NO-DATE` are control-function decisions (expose the
column? force a date bound on that partitioned table?). Confirm the live schema
loader reads all real tables + partition flags correctly (it uses `.Q.pt` +
`cols`).

## 4. seccomp-bpf — prove it engages in the FULL chain on native Linux

I could only verify the seccomp layer on WSL2, which forces the `rbind-ro+mask`
fallback (strategy B) where python3 can't initialise, so the innermost seccomp
wrapper SKIPS there. On your native-Linux box the runner uses **strategy A
(minimal-rootfs)** and python3 works, so seccomp should actually engage.

```bash
bash aegis/deploy/confine_adversarial_test.sh      # expect the seccomp assertion to PASS, not SKIP
```
- Confirm the line "seccomp-bpf killed a blocked syscall (unshare) inside the
  sandbox" PASSES (strategy A path).
- Run a representative real agent payload under `confine_run.sh` and confirm it
  runs normally (no benign syscall tripped the deny-list — if a real payload
  dies with SIGSYS, capture which syscall via `dmesg`/`auditd` and tell me;
  we may need to allow it).
- Sanity-check the x86_64 syscall numbers against your kernel
  (`ausyscall <name>` or `/usr/include/asm/unistd_64.h`) — I hand-coded the
  table; a wrong number would either miss a dangerous syscall or kill a benign
  one.

## 5. Adversarial re-run

Re-run the uncooperative-attacker corpus (A01-A30) end-to-end with all of the
above active and confirm attack-success stays 0/30 and the benign
served-and-correct rate is unchanged. The combine-semantics change is the one
most likely to move the benign number (over-restriction) — watch for it.

---

**Report back:** suite result (30/30?), per-principal entitlement diff, P1/P2 at
real scale, schema-diff findings triage, the seccomp assertion result + any
benign payload that tripped it, and the adversarial scoreboard. Once entitlement
combine is signed off on real data, this branch is ready to merge to main.
