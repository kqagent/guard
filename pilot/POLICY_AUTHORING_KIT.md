# Control-function policy authoring kit (item B4)

Turnkey for a control function / 2nd line to author, validate, and sign the real
analyst policy — and set up the real-data re-soak — **without engineering help**.

## 1. Author from the template

Copy `pilot/policy.kdb.template.json` to your own file and fill every
`REPLACE`/`EDIT` marker with your real values:

- **`query_proxy.allowed_tables`** — the tables the analyst agent may read.
- **`query_proxy.require_date_tables`** — the partitioned subset (a date range is
  required on these; must be a subset of `allowed_tables`).
- **`query_proxy.columns`** — the per-table column allowlist. *Every* allowed
  table needs one, or structured queries naming its columns are rejected.
- **`query_proxy.agg_fns`** — the aggregations you permit (from the compiler's set).
- **`pii_egress.sensitive_terms`** — your classified-data vocabulary.
- **`prod.patterns`** — your production markers (hostnames, ports, mount paths).
- Leave `grants.tools` as the two analyst tools — **never** add `run_query`
  (free-form q is break-glass; see `BREAK_GLASS.md`).

## 2. Validate (no engineering needed)

```
python -m aegis.policy_lint your-policy.kdb.json --strict
```

It checks structural integrity and reports gaps — e.g. an allowlisted column whose
table isn't declared, `require_date_tables` not a subset of `allowed_tables`, an
allowed table with no column allowlist (a silent usability gap), an invalid
`prod.patterns` regex, an unknown pack, a bad `max_rows`, or free-form `run_query`
slipping into `grants`. `--strict` makes warnings fail too. Iterate until **PASS**.

It validates *well-formedness*, not your security *choices* — those are yours.

## 3. Sign

```
python aegis/deploy/build_bundle.py ./bundle --policy your-policy.kdb.json
```

Produces `policy.json` + Ed25519 `policy.json.sig` + `pubkey.hex`. Move the
private key to your HSM/KMS and delete it from disk. Pin `pubkey.hex` on the PDP.
(`bundle*/` is gitignored — never commit the key.)

## 4. Verify the deployment manifest

```
python tools/verify_deployment.py your-cluster/agent.yaml
```

Must report **hardened** (read-only rootfs, non-root, dropped caps, seccomp, no
host namespaces, egress proxy, read-only policy mount, out-of-process PDP, …).

## 5. Set up the real-data re-soak (the gate only you can close)

The pilot's FP/coverage numbers are on a representative corpus against a sample
schema. To close the enforce go/no-go you must re-soak on **your** desk corpus and
data:

1. Point `pilot/policy.fsp.json`-style config at your tables (or use your signed
   policy directly).
2. Replace `pilot/corpus.json` benign tasks with **real analyst questions** your
   desk actually runs, and re-run `pilot/validate_structured.py` — target: your
   corpus covered with 0 compiler rejects (anything rejected is either a real gap
   to add as a reviewed grammar slot, or a query that shouldn't run).
3. Run the live structured soak (`pilot/fsp_soak.py`) and score with
   `pilot/score_structured.py`: 0 compiler rejects, 0 malicious harm.
4. Run `pilot/adversarial_recall.py` for the gate's targeted-attack-success-rate.

When those hold on your data, the FP/recall gate in `ASSESSMENT.md` is met for
your deployment.
