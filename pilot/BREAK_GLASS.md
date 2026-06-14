# Break-glass surface — structural separation (item B3)

Free-form `run_query` (arbitrary q) is **not** part of the analyst product. It is
a deny-list on a Turing-complete language; the analyst surface is the structured
compiler. But there are legitimate admin/incident cases for free-form q, so it
exists as an explicitly-separated **break-glass** path.

## The separation (structural, not procedural)

1. **Not in any analyst grant.** `pilot/policy.fsp.json` `grants.tools` is
   `[run_structured_query, read_file]`. Free-form `run_query` is absent, so the
   gate default-denies it for *every* principal on the analyst bundle
   (`DENY-TOOL-NOT-GRANTED`). An analyst cannot reach it, full stop.
2. **Separate, separately-signed bundle.** `pilot/policy.breakglass.json` is a
   distinct policy, signed by a **distinct key**, and must never be the bundle
   mounted for the analyst PDP. It grants `run_query` and adds `rbac` with
   `default_deny`: only the named `breakglass-admin` principal is authorised;
   `"*": {allow_tools: []}` denies everyone else (incl. any analyst principal) —
   so even if this bundle were mis-mounted, an analyst principal is rbac-denied.
3. **Same hard controls still apply.** `kdb_guard` is enabled on the break-glass
   bundle too: an admin's free-form `system "id"` / `hopen` / mutation is still
   blocked. Break-glass widens *who can submit q*, not *what q is allowed*.
4. **Audited + tripwire-escalated.** Every break-glass action is audited; the
   break-glass supervisor lists `BREAK-GLASS-USED` (and PRD/PII/system rules) as
   `critical_rules`, so any flagged break-glass use raises an incident
   immediately, and repeated use trips the breaker. The default posture is "any
   break-glass use is an event someone reviews."
5. **Confinement underneath.** The q process is non-root / read-only HDB / no
   shell / egress-blocked regardless of surface — the load-bearing containment if
   the deny-list is ever bypassed.

## Proof

`pilot/breakglass_test.py` (PASS): analyst principal blocked on the analyst policy
(`DENY-TOOL-NOT-GRANTED`) **and** on the break-glass bundle (`RBAC-TOOL-DENIED`);
analyst can use `run_structured_query`; `breakglass-admin` can use `run_query`; but
the admin's dangerous free-form is still blocked (`KDB-Q-SYSTEM-EXEC`).

## Operational note

To grant break-glass: sign `policy.breakglass.json` with the admin key, mount it on
a *separate* admin PDP endpoint (not the analyst PDP), and have the admin act as
`breakglass-admin`. Rotate/destroy the grant after the incident. Never merge the
break-glass grant into the analyst bundle.
