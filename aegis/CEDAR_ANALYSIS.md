# Cedar Analysis CLI corroboration (optional-tier)

Independent, differently-implemented corroboration of Aegis's own grant-algebra
proofs, using AWS's open-source **Cedar** analysis tooling (CVC5-backed,
Lean-proven). **Corroboration only — Aegis is NOT rebuilt on Cedar.**

## What it does

`aegis/cedar_analysis.py` exports the policy's authz subset to Cedar text (via
`cedar_export.py`) and feeds it to the Cedar CLI:
- **validate** — the exported policy parses and validates under Cedar's analyzer.
- **--equiv a.cedar b.cedar** — policy-equivalence between two versions (the same
  narrowing/widening question `monotonic_confinement` answers, cross-checked by a
  separate SMT engine).

The assurance story then has two independent provers behind the core properties:
Aegis's own (`formal.py` exhaustive over the modeled universe; `formal_smt` with
Z3 over unbounded domains) **and** AWS Cedar/CVC5.

## Dependency (flagged, not bundled)

Needs the Cedar Analysis CLI installed (Rust toolchain): `cedar` or
`cedar-policy-cli` on PATH, or `AEGIS_CEDAR_BIN=<path>`. Install e.g.:

```
cargo install cedar-policy-cli          # validate/parse
# the SMT analysis CLI (policy-equivalence) ships in the cedar-spec repo
```

## CI behaviour

OPTIONAL-tier: when the Cedar CLI is absent the runner **skips cleanly** (shown as
`skip` in `run_all_checks`, like `formal_smt` / `q_conformance_test`), so CI
without Cedar stays green. When present, it runs and reports the verdict. On this
estate the tool is not installed, so it currently skips — the runner + export are
built and ready; installing Cedar turns the corroboration on with no code change.
