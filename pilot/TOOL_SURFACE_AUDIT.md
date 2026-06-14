# Tool-surface audit — allowlist (enumerate-goodness) discipline (item B)

Every tool the analyst agent can hold, classified: does it enumerate GOODNESS
(allowlist, default-deny) or BADNESS (deny-list / nothing)? Anything not
enumerate-goodness is a finding. The lesson from the file-plane finding stands:
the allowlist discipline must apply to *every* tool, not just the query tool.

| tool | control | enumerate | verdict |
|---|---|---|---|
| `run_structured_query` | `query_compiler` — request validated field-by-field against table/column/op/agg/window allowlists; only `select/exec/meta/aj` emitted; `_DANGEROUS_Q` backstop on output | **goodness** | ✅ primary analyst query surface |
| `read_file` | `file_access` pack — gate-level path allowlist (read only from designated roots); traversal denied; pilot also scratch-scopes the executor | **goodness** | ✅ |
| `run_query` (free-form q) | `QueryGuard` proxy + `_DANGEROUS_Q` deny-list | **badness** (deny-list on a Turing-complete language) | ⚠️ **BREAK-GLASS ONLY** — removed from the analyst grant + tool surface; behind `--free-form`; its recall is measured adversarially in item D |

## Decisions

1. **`run_query` removed from the analyst surface entirely.** `policy.fsp.json`
   `grants.tools` is now `["run_structured_query", "read_file"]` — the analyst
   agent cannot invoke free-form q at all (gate default-denies it). Break-glass
   use requires a *separate, explicitly-signed* policy that grants `run_query`
   to an admin principal — never the analyst's policy. The pilot's `--free-form`
   flag is a test affordance, not the analyst surface.
2. **`read_file` is enumerate-goodness** at the gate (`file_access` allowlist) —
   the file-plane twin of the query allowlist. No change needed.
3. **The structured query surface is enumerate-goodness** by construction.

## Residual / honest

- The break-glass `run_query` path remains deny-list-based. That is acceptable
  *only* because (a) it is not on the analyst surface, (b) it requires a separate
  signed grant, and (c) confinement is load-bearing underneath. Its true recall
  (deny-list, not model conscience) is measured in item D against an adversarial
  driver — that number, not this audit, decides whether break-glass is ever safe
  to grant.
- Any FUTURE tool added to the agent must pass this same test before grant:
  allowlist or it doesn't ship.
