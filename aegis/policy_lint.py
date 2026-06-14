"""Policy authoring validator (item B4) — turnkey for a control function.

A bank authors its real policy (real tables/columns/sensitive terms/prod markers)
and runs this to confirm the policy is WELL-FORMED before signing it — without
engineering help. It checks structural integrity and reports gaps; it does not
judge the security *choices* (that is the control function's call), only that the
policy is internally consistent and won't misbehave at runtime.

    python -m aegis.policy_lint path/to/policy.kdb.json
    python -m aegis.policy_lint path/to/policy.kdb.json --strict   # warnings fail too

Exit 0 = no errors; 1 = errors (or warnings under --strict); 2 = unreadable.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_KNOWN_PACKS = {
    "secrets", "kdb_guard", "exfiltration", "pii_egress", "destructive_ops",
    "prod_protection", "resource_guard", "rbac", "command_allowlist",
    "kdb_code_quality", "tool_rules", "mcp_manifest", "cost_budget",
}
_AGG_FNS = {"avg", "sum", "min", "max", "count", "first", "last", "wavg", "wsum",
            "dev", "var", "med", "cor", "countdistinct"}


def lint(policy: dict) -> tuple[list[str], list[str]]:
    """Return (errors, warnings). Errors mean the policy is malformed."""
    errs: list[str] = []
    warns: list[str] = []

    def err(m): errs.append(m)
    def warn(m): warns.append(m)

    # -- top level --
    if policy.get("fail_mode") != "closed":
        warn("fail_mode is not 'closed' — Aegis is designed to fail closed; confirm this is intended.")
    if "enabled_packs" not in policy:
        err("missing required 'enabled_packs'.")
    for p in policy.get("enabled_packs", []):
        if p not in _KNOWN_PACKS:
            err(f"enabled_packs references unknown pack '{p}'.")

    # -- grants --
    grants = policy.get("grants", {})
    tools = grants.get("tools")
    if tools is None:
        warn("grants.tools absent — the engine will be detector-only (no default-deny on tools).")
    elif "run_query" in (tools or []):
        warn("grants.tools includes free-form 'run_query' — this should be a break-glass/admin "
             "bundle, never the analyst surface (see BREAK_GLASS.md).")

    # -- query_proxy / compiler config (the primary control's allowlists) --
    qp = policy.get("query_proxy", {})
    allowed = {t.lower() for t in qp.get("allowed_tables", [])}
    req_date = {t.lower() for t in qp.get("require_date_tables", [])}
    cols = qp.get("columns", {})
    if not allowed:
        warn("query_proxy.allowed_tables is empty — no table can be queried.")
    # require_date_tables must be a subset of allowed_tables
    for t in req_date - allowed:
        err(f"require_date_tables has '{t}' which is not in allowed_tables.")
    # every allowed table SHOULD have a column allowlist (else structured queries
    # on it fail closed at runtime — a silent usability gap)
    for t in allowed:
        if t not in {k.lower() for k in cols}:
            warn(f"allowed table '{t}' has no column allowlist in query_proxy.columns — "
                 "structured queries naming its columns will be rejected.")
    # column allowlist tables should be in allowed_tables
    for t in cols:
        if t.lower() not in allowed:
            warn(f"query_proxy.columns declares table '{t}' not in allowed_tables.")
        c = cols[t]
        if not isinstance(c, list) or not all(isinstance(x, str) for x in c):
            err(f"query_proxy.columns['{t}'] must be a list of column-name strings.")
        else:
            for name in c:
                if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", name):
                    err(f"query_proxy.columns['{t}'] has invalid column identifier '{name}'.")
    af = qp.get("agg_fns")
    if af is not None:
        for fn in af:
            if fn not in _AGG_FNS:
                warn(f"query_proxy.agg_fns includes '{fn}' which the compiler does not implement.")
    mr = qp.get("max_rows")
    if mr is not None and (not isinstance(mr, int) or mr <= 0):
        err(f"query_proxy.max_rows must be a positive int, got {mr!r}.")

    # -- pii / prod markers present (warn if a real deployment left them empty) --
    if not policy.get("pii_egress", {}).get("sensitive_terms"):
        warn("pii_egress.sensitive_terms is empty — declare your classified-data vocabulary.")
    if not policy.get("prod", {}).get("patterns"):
        warn("prod.patterns is empty — declare your production markers (ports, paths, hostnames).")
    for pat in policy.get("prod", {}).get("patterns", []):
        try:
            re.compile(pat)
        except re.error as e:
            err(f"prod.patterns has an invalid regex {pat!r}: {e}.")

    # -- rbac well-formedness (if present) --
    rbac = policy.get("rbac", {})
    for pr, rule in rbac.get("principals", {}).items():
        if not isinstance(rule, dict) or not ({"allow_tools", "deny_tools"} & set(rule)):
            warn(f"rbac principal '{pr}' has neither allow_tools nor deny_tools — it grants nothing/everything by default.")

    # -- protected_paths sanity --
    if grants.get("tools") and not policy.get("protected_paths"):
        warn("no protected_paths declared — the agent's own policy/audit are not protected from a file tool.")

    return errs, warns


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    strict = "--strict" in sys.argv
    if not args:
        print("usage: python -m aegis.policy_lint <policy.json> [--strict]")
        return 2
    path = Path(args[0])
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"cannot read/parse {path}: {e}")
        return 2

    errs, warns = lint(policy)
    print(f"=== policy lint: {path.name} ===")
    for e in errs:
        print(f"  ERROR  {e}")
    for w in warns:
        print(f"  warn   {w}")
    if not errs and not warns:
        print("  clean — no errors, no warnings.")
    print(f"\n{len(errs)} error(s), {len(warns)} warning(s).")
    failed = bool(errs) or (strict and bool(warns))
    print("FAIL" if failed else "PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
