# Deploying Aegis

Three paths, smallest to largest. All end with the same guarantee: the agent's
actions are decided by a signed policy in a process the agent cannot tamper
with, fail-closed, with a tamper-evident audit and an automated kill switch.

> First principle: **deploy in monitor mode, measure the false-positive rate on
> real traffic, then flip to enforce.** See `PILOT.md` for the staged gates.

---

## 0. Prerequisites

- Python ≥ 3.10 (the enforcement core is stdlib-only; `cryptography` is needed
  only for Ed25519 signing and is installed by the quickstart).
- For containers: Docker + the compose plugin.
- For the kdb+ query plane: a licensed `q` on the box (or reachable).

---

## 1. Evaluate in one command (bare metal)

For a client who just wants to see it run:

```bash
git clone <repo> && cd aegis-guardrails
./quickstart.sh            # Linux/macOS
#  .\quickstart.ps1        # Windows
```

This creates a venv, installs Aegis, builds a **signed** policy bundle, runs the
full acceptance suite (must be green), starts the out-of-process PDP, and then
**proves** the gate live: a benign action is allowed, a destructive one blocked.
A clean run *is* the demo. The PDP stops when the script exits; for a persistent
service use path 2 or the systemd unit below.

---

## 2. Containers (recommended for a pilot)

```bash
deploy/docker_up.sh         # builds the signed bundle, brings up the stack, health-checks
deploy/docker_up.sh down    # tear down
```

Three services (see `aegis/deploy/docker-compose.yml`):

| service | role | privilege |
|---|---|---|
| `aegis-pdp` | policy decision point; signed bundle mounted **read-only**; audit | control plane |
| `aegis-egress` | egress forward proxy (host allowlist + SSRF + payload DLP) | control plane |
| `governed-agent` | the workload — read-only rootfs, non-root, caps dropped, **no direct egress** | sandboxed |

The agent reaches the network only via the egress proxy and gets every
decision from the PDP. Verify the hardening of the manifest before trusting it:

```bash
python tools/verify_deployment.py aegis/deploy/k8s.yaml   # must be 12/12 controls
```

---

## 3. Kubernetes (production)

`aegis/deploy/k8s.yaml` is a reference hardened Deployment + a default-deny
egress NetworkPolicy. Gate it in CI:

```bash
python tools/verify_deployment.py <your-manifest>.yaml    # fail the pipeline if < 12/12
```

Run the PDP and egress proxy in a higher-privilege `aegis-system` namespace; the
agent workload in a locked-down namespace that can only reach those two.

### systemd unit for the PDP (non-container hosts)

```ini
# /etc/systemd/system/aegis-pdp.service
[Service]
ExecStart=/opt/aegis/.venv/bin/python -m aegis.pdp_service \
  --policy /etc/aegis/policy.json --sig /etc/aegis/policy.json.sig \
  --pubkey <PINNED_PUBKEY_HEX> --audit /var/aegis/audit.jsonl --port 8787
User=aegis
ReadOnlyPaths=/etc/aegis
NoNewPrivileges=true
Restart=always
```

---

## The signed policy bundle

The policy is owned by the **control function**, not engineering. Build and sign:

```bash
python aegis/deploy/build_bundle.py ./bundle          # fresh Ed25519 keypair
#  -> bundle/policy.json, policy.json.sig, pubkey.hex, private.key.KEEP-SECRET
```

- Move `private.key.KEEP-SECRET` to an HSM/KMS and delete it from disk. The PDP
  is started with **only** the public key (`--pubkey`), so it can verify but not
  forge; a tampered policy fails closed (the builder self-tests this).
- Mount the bundle **read-only** to the agent's uid. Signing closes forgery;
  the read-only mount closes editing. Both together = the agent can neither
  rewrite nor re-sign its own guardrails.
- Re-run `build_bundle.py` to roll the policy; restart the PDP.
- Optional: `python -m aegis.cedar_export` emits the authz subset as Cedar for
  review in AWS/Cedar tooling.

---

## Authoring your policy

Edit `aegis/policy.json` (general/shell agents) or `aegis/policy.kdb.json`
(kdb+ analyst agents), then rebuild the bundle. Set for your environment:

- `grants` — the exact tools/binaries/writable paths the agent may use (default-deny).
- `query_proxy.allowed_tables` / `require_date_tables` — your real kdb+/SQL schema.
- `pii_egress.sensitive_terms`, `egress.allowlist_hosts`, `prod.patterns` — your
  classified-data vocabulary, approved hosts, prod markers.
- `supervisor` — tripwires + kill strategy (below).

---

## Runtime supervisor + kill switch (second line of defence)

`policy.*.json` → `supervisor` block. The deterministic supervisor watches the
*sequence* of decisions and trips a per-principal circuit breaker on tripwires
(critical rule fired, repeated blocks, escalation rate, approval abuse,
unclassified action). On trip it blocks all further actions from that principal
**and** fires the kill switch:

```json
"supervisor": {
  "enabled": true,
  "enforce_in_monitor": false,            // monitor: record incidents, don't kill
  "kill": {"strategy": "command",
           "command": ["docker", "kill", "{container}"]},   // or signal / callback / none
  "tripwires": { "critical_rules": {"rule_ids": ["PRD-PROTECTED-PATH","PII-EGRESS"]},
                 "repeated_blocks": {"max_blocks": 3} }
}
```

Incidents are written to `incident_dir` (json + human-readable txt with a
timeline). Operator CLI:

```bash
aegis-supervisor status              # tripped breakers
aegis-supervisor incidents           # list incidents
aegis-supervisor show INC-...        # one incident
aegis-supervisor reset <principal>   # clear a breaker after handling
```

**Optional LLM overseer** (`aegis.overseer`, defence-in-depth): a *separate*
model reads the redacted audit timeline and flags intent drift / staged attacks
the rules can't enumerate, and narrates incidents for on-call. Advisory only —
it never replaces the deterministic breaker. Needs an Anthropic key; the gate
runs fine without it.

---

## Audit / WORM (regulated finance)

Point the audit at a write-once sink so the record survives host compromise
(`aegis/worm_sinks.py`: syslog / HTTP append / S3 Object-Lock / file-on-WORM-mount).
For regulated surfaces set `strict_sinks=True` — then a decision that cannot be
durably recorded fails closed ("no record, no decision"). The chain is verifiable
(`AuditLog.verify` / `verify_against_anchor` detects truncation/rewind).

---

## Integrate your agent

```python
from aegis.guard import Guard
guard = Guard.remote("http://aegis-pdp:8787")     # out-of-process PDP

decision = guard.check(tool_name, tool_args, principal=session_id)
if decision.effect.value == "block":
    result = Guard.refusal_text(decision)          # feed back to the model
elif decision.effect.value == "require_approval":
    result = await your_approval_flow(decision)
else:
    result = run_tool(tool_name, tool_args)
```

For function-calling loops, `aegis.sdk.AegisSession` wraps a whole tool registry
(gate → approve → execute → charge). For kdb+ specifically,
`aegis.live_kdb_agent` is a worked example of an LLM agent whose `run_query`
calls pass through the query proxy before touching q.
```
