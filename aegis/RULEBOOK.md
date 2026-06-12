# Aegis rulebook — the dos and don'ts

Every rule is a deterministic detector. Severity maps to an effect:

| Effect | Meaning |
|---|---|
| **block** | the action never runs; reason fed back to the model |
| **require_approval** | a human must confirm before it runs |
| **allow** | proceeds (logged, silent) |

Effects are configurable per pack in `policy.json` — the control function can
downgrade/upgrade any pack without code changes. "Most severe wins" when
several rules fire on one action.

Packs marked **(opt-in)** are implemented and tested but not in
`enabled_packs` by default — they need site config (principals / approved
binaries) first.

---

## secrets — credentials must never appear in code, commands, or prompts

| Rule | Fires on |
|---|---|
| `SEC-AWS-ACCESS-KEY` | `AKIA…` access key id |
| `SEC-AWS-SECRET-KEY` | `aws_secret_access_key = …` |
| `SEC-GCP-API-KEY` | `AIza…` Google API key |
| `SEC-GCP-SA-KEY` | GCP service-account `private_key_id` |
| `SEC-AZURE-CONN` | Azure storage connection string with `AccountKey` |
| `SEC-PRIVATE-KEY-BLOCK` | `-----BEGIN … PRIVATE KEY-----` |
| `SEC-SLACK-TOKEN` / `SEC-GITHUB-TOKEN` / `SEC-STRIPE-KEY` | provider tokens |
| `SEC-JWT` | a JWT (`eyJ….eyJ….…`) |
| `SEC-BEARER-TOKEN` | `Authorization: Bearer …` |
| `SEC-GENERIC-ASSIGNMENT` | `password=` / `api_key:` / `secret=` with a value |
| `SEC-CONN-STRING-CREDS` | `postgres://user:pass@host` style creds |

**Do:** reference secrets via a vault handle. **Evidence is masked** before it
reaches the audit log.

## exfiltration — data must not leave to non-allowlisted destinations

| Rule | Fires on |
|---|---|
| `EXF-EGRESS-HOST` | curl/wget/scp/ssh/rsync/`requests`/`/dev/tcp`/`aws s3 cp`/`gsutil`/mail to a host **not** in `egress.allowlist_hosts` |
| `EXF-EGRESS-OPAQUE` | egress intent with no resolvable destination → **approval** |

## pii_egress — classified data leaving (data-classification aware)

| Rule | Fires on |
|---|---|
| `PII-EGRESS` | any egress action whose text references a `sensitive_terms` token (`positions`, `pnl`, `mnpi`, `ssn`, `iban`, `account_no`, …) |

This is the one that caught the live Haiku model exfiltrating `positions.csv`.

## destructive_ops — irreversible / wide-blast-radius mutations

`DST-RM-RECURSIVE-FORCE`, `DST-RM-GLOB`, `DST-GIT-FORCE-PUSH`,
`DST-GIT-HARD-RESET`, `DST-GIT-CLEAN`, `DST-SQL-DROP`, `DST-SQL-TRUNCATE`,
`DST-SQL-DELETE-UNBOUNDED`, `DST-Q-DELETE`, `DST-Q-HDEL`, `DST-DISK-WIPE`
(`dd`/`mkfs`/`shred`), `DST-RECURSIVE-CHMOD-CHOWN`, `DST-CHMOD-777`,
`DST-KILL-SIGNAL`, `DST-SERVICE-STOP`, `DST-FIREWALL-FLUSH`,
`DST-CRONTAB-WIPE`, `DST-DOCKER-PRUNE`, `DST-K8S-DELETE`.

## prod_protection — production targets + the guardrails themselves

| Rule | Fires on |
|---|---|
| `PRD-TARGET` | text matching any `prod.patterns` regex (`prod`, `:2000`, `/mnt/prod`, …) |
| `PRD-PROTECTED-PATH` | touching any `protected_paths` entry — **including `policy.json`, the engine, and the audit dir**, so an agent cannot disable its own guardrails |

## resource_guard — runaway queries/loops that degrade prod systems

| Rule | Fires on | Default |
|---|---|---|
| `RES-UNBOUNDED-SCAN` | `select … from <big table>` with no `where date` / row limit | approval |
| `RES-INFINITE-LOOP` | `while[1]` / `while true` | approval |

`big_tables` is configured per site. This is the "don't let the agent stall
the tickerplant" control.

## rbac — per-principal tool authorization **(opt-in)**

| Rule | Fires on |
|---|---|
| `RBAC-TOOL-DENIED` | principal not granted the tool it's using |
| `RBAC-UNPROVISIONED` | unknown principal when `default_deny: true` |

Configure under `rbac.principals` (`{principal: {allow_tools/deny_tools}}`).

## command_allowlist — default-deny shell **(opt-in)**

| Rule | Fires on |
|---|---|
| `CMD-NOT-ALLOWLISTED` | the binary of any pipeline segment is not in `command_allowlist.binaries` |

The strongest operational posture: nothing runs unless explicitly approved.

---

## Adding a rule

1. Add a pattern to the relevant list in `detectors.py` (or write a new
   detector function and register it in `DETECTORS`).
2. If it's a new pack, name it in `policy.json → enabled_packs` and add its
   config block.
3. Add a scenario to `demo.py` with the expected effect — it's the
   acceptance test, so a new rule isn't "done" until the demo asserts it.

## Tuning without code

The control function edits `policy.json` only: allowlists, sensitive terms,
prod patterns, big tables, per-pack effects, principals, approved binaries.
No engine change, no redeploy of logic — just a new signed bundle.
