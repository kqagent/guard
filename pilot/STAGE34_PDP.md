# Stage 3-4 — out-of-process PDP, Guard.remote, WORM audit (homer)

*2026-06-14. Moves the FSP pilot toward enforce-readiness: the gate runs in a
process the agent cannot tamper with, against a signed read-only policy bundle,
with a tamper-evident audit mirrored to a WORM sink. Still monitor-mode for the
agent surface — this exercises the enforcement plane, not a cutover.*

## What was stood up

1. **Signed policy bundle** — `python aegis/deploy/build_bundle.py ./bundle-fsp
   --policy pilot/policy.fsp.json` → `policy.json` + Ed25519 `policy.json.sig` +
   `pubkey.hex`. Private key emitted to `private.key.KEEP-SECRET` (gitignored;
   move to HSM/KMS in prod). Bundle self-test: valid loads clean, tampered fails
   closed.

2. **Out-of-process PDP** —
   `python -m aegis.pdp_service --policy bundle-fsp/policy.json
   --sig bundle-fsp/policy.json.sig --pubkey <hex>
   --audit .aegis/fsp-pdp-audit.jsonl --host 127.0.0.1 --port 8788`.
   The policy is loaded with the pinned pubkey → any unsigned/tampered policy
   makes the engine fail closed (block everything).

3. **Agent → `Guard.remote("http://127.0.0.1:8788")`** — gate decisions come from
   the sidecar over HTTP, not in-process. (The QueryGuard proxy stays in-process
   on the query plane; the PDP is the policy decision point for the gate.)

## Proven (`python -m pilot.stage34_pdp`)

| property | result |
|---|---|
| remote gate, benign read | **allow** |
| remote gate, `select system "rm -rf …"` | **block** `KDB-Q-SYSTEM-EXEC`, `DST-RM-RECURSIVE-FORCE` |
| remote gate, embedded `hopen` exfil | **block** `KDB-Q-CONN` |
| remote gate, unbounded scan | **require_approval** `RES-UNBOUNDED-SCAN` |
| remote gate, read protected path | **block** `PRD-PROTECTED-PATH` |
| **PDP unreachable** | **block** (fail-closed — the watertight prod placement) |
| **audit tamper** (edit a past verdict) | **detected** — `entry_hash mismatch` |
| **WORM mirror** | blocked decision mirrored to the off-host sink |
| **broken WORM sink + `strict_sinks`** | `SinkError` raised → fail-closed |

The new `kdb_guard` pack enforces **over the PDP** — i.e. the system-command
guardrail holds in the out-of-process, signed-bundle configuration, not just
in-process.

## Notes / residual

- The signed bundle has `supervisor.enabled` (circuit breaker). The demo isolates
  principals per probe so the breaker doesn't mask per-action verdicts; the
  breaker itself is covered by `supervisor_test` and trips on repeated blocks
  (writes `.aegis/incidents/INC-*.json`).
- `pdp_service` exposes `--audit` (local hash-chained log); the WORM **sink**
  wiring (`worm_sinks.py`, `strict_sinks`) is demonstrated at the `AuditLog`
  level. Production: point a sink at syslog/S3-Object-Lock/HTTP-append and run the
  PDP behind it. A small `--sink`/`--strict` CLI passthrough on `pdp_service` is a
  reasonable follow-up.
- Acceptance gates #1/#3 (suite 23/23, signed-bundle tamper-reject) hold on this
  commit; remaining for enforce sign-off: widened-corpus FP gate (Stage 2) +
  control-function review of the kdb_guard/cap changes.
