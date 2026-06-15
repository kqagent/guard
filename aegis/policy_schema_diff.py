"""Policy-correctness / schema-drift linter.

A signed policy is authored against the estate's schema at a point in time. The
estate then changes - a column is dropped, a table is renamed, a new table
appears, a partitioned table is added. When that happens the policy can SILENTLY
become wrong in two dangerous directions:

  * TOO TIGHT (availability): an entitlement filters on a column the table no
    longer has, or on a column that isn't in the agent's allowlist -> every
    query by that principal compiles to a predicate on a missing column and
    fails closed. The principal is locked out and nobody notices until they
    complain.
  * TOO LOOSE (safety): a newly-added partitioned table is in `allowed_tables`
    but NOT in `require_date_tables` -> the compiler won't force a date bound,
    so an agent can full-scan the whole history. Or a brand-new column appears
    on a table and the control function never decided whether to expose it.

This tool diffs a policy against a schema and reports both classes. The schema
comes either from a live HDB (queried via q) or a static JSON snapshot (so it
runs in CI with no kdb+). The diff LOGIC is pure and stdlib-only; only live mode
needs q.

ERRORs fail the lint (exit 1); WARNs are surfaced for the control function to
judge. Run it whenever the estate schema changes, or in CI against a checked-in
schema snapshot, before re-signing a policy.

Usage:
    python -m aegis.policy_schema_diff --policy aegis/policy.json --schema schema.json
    python -m aegis.policy_schema_diff --policy aegis/policy.json --hdb /data/hdb
    python -m aegis.policy_schema_diff ... --json        # machine-readable findings
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Finding levels.
ERROR, WARN, INFO = "ERROR", "WARN", "INFO"


class Finding:
    __slots__ = ("level", "code", "message")

    def __init__(self, level: str, code: str, message: str):
        self.level, self.code, self.message = level, code, message

    def __repr__(self):
        return f"{self.level:5} [{self.code}] {self.message}"

    def as_dict(self):
        return {"level": self.level, "code": self.code, "message": self.message}


# -- policy / schema extraction -------------------------------------------

def _policy_view(policy: dict) -> dict:
    """Pull the schema-relevant parts of a policy into a flat, lowercased view."""
    qp = policy.get("query_proxy", {}) or {}
    ent = policy.get("entitlements") or qp.get("entitlements") or {}
    return {
        "allowed": {t.lower() for t in qp.get("allowed_tables", [])},
        "req_date": {t.lower() for t in qp.get("require_date_tables", [])},
        "columns": {t.lower(): {c.lower() for c in v}
                    for t, v in (qp.get("columns", {}) or {}).items()},
        "ent_mode": ent.get("mode", "open"),
        # {principal -> {table-or-"*" -> [filter dicts]}}
        "ent": {p: {(t.lower() if t != "*" else "*"): (rule.get("row_filters", {}) or {}).get(t, [])
                    for t in (rule.get("row_filters", {}) or {})}
                for p, rule in (ent.get("principals", {}) or {}).items()},
    }


def normalise_schema(raw: dict) -> dict:
    """Accept a schema JSON of the form
        {"tables": {"trade": {"columns": [...], "partitioned": true}, ...}}
    (or the bare {"trade": {...}} mapping) and return a lowercased view:
        {table: {"columns": set, "partitioned": bool}}."""
    tables = raw.get("tables", raw)
    out = {}
    for t, spec in tables.items():
        cols = spec.get("columns", spec) if isinstance(spec, dict) else spec
        out[t.lower()] = {
            "columns": {c.lower() for c in cols},
            "partitioned": bool(spec.get("partitioned", False)) if isinstance(spec, dict) else False,
        }
    return out


def schema_from_hdb(hdb_path: str) -> dict:
    """Live mode: load the HDB in q and read each table's columns + whether it is
    partitioned (.Q.pt). Needs a q binary (see aegis.qexec)."""
    from .qexec import q_run
    prog = (f'system "l {hdb_path}";\n'
            'pt:.Q.pt;\n'
            '{ -1 "TABLE ",(string x)," PART ",(string `long$x in pt)," COLS ",'
            '(" " sv string cols x); } each tables`;\n'
            'exit 0;')
    out = q_run(prog, workdir="/tmp/aegis_schema", timeout=120)
    tables = {}
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("TABLE "):
            continue
        # TABLE <name> PART <0|1> COLS c1 c2 ...
        try:
            _, name, _, part, _, *cols = line.split()
        except ValueError:
            continue
        tables[name.lower()] = {"columns": {c.lower() for c in cols},
                                "partitioned": part == "1"}
    if not tables:
        raise RuntimeError(f"could not read any table schema from HDB at {hdb_path}:\n{out}")
    return tables


# -- the diff --------------------------------------------------------------

def diff(policy: dict, schema: dict) -> list[Finding]:
    """Return findings comparing a policy to a schema (both already loaded)."""
    pv = _policy_view(policy)
    schema = {t.lower(): v for t, v in schema.items()}
    f: list[Finding] = []

    allowed, req_date, cols, ent = pv["allowed"], pv["req_date"], pv["columns"], pv["ent"]

    # internal consistency (no schema needed) ------------------------------
    for t in cols:
        if t not in allowed:
            f.append(Finding(ERROR, "COLS-TABLE-UNKNOWN",
                             f"`columns` defines table '{t}' that is not in allowed_tables"))
    for t in req_date:
        if t not in allowed:
            f.append(Finding(ERROR, "REQDATE-TABLE-UNKNOWN",
                             f"require_date_tables lists '{t}' that is not in allowed_tables"))

    # per allowed table vs live schema -------------------------------------
    for t in sorted(allowed):
        if t not in schema:
            f.append(Finding(ERROR, "TABLE-MISSING",
                             f"allowed table '{t}' does not exist on the estate"))
            continue
        real = schema[t]["columns"]
        partitioned = schema[t]["partitioned"]
        for c in sorted(cols.get(t, set())):
            if c not in real:
                f.append(Finding(ERROR, "COL-MISSING",
                                 f"allowlisted column '{t}.{c}' no longer exists on the table"))
        if t in cols:   # only flag new columns when an allowlist exists for the table
            for c in sorted(real - cols[t]):
                f.append(Finding(WARN, "NEW-COL",
                                 f"table '{t}' has column '{c}' not in the allowlist "
                                 "(default-deny hides it; decide whether to expose it)"))
        if partitioned and t not in req_date:
            f.append(Finding(WARN, "PART-NO-DATE",
                             f"table '{t}' is partitioned but not in require_date_tables "
                             "(agent can full-scan history; unbounded materialisation risk)"))
        if t in req_date and not partitioned:
            f.append(Finding(ERROR, "DATE-NOT-PART",
                             f"require_date_tables expects '{t}' partitioned, but it is not "
                             "(the forced date predicate will type-error)"))

    # entitlements ---------------------------------------------------------
    for principal, rules in ent.items():
        if not rules:
            f.append(Finding(WARN, "PRINCIPAL-NORULES",
                             f"principal '{principal}' has no row_filters"
                             + (" (default-deny -> can query nothing)" if pv["ent_mode"] == "default_deny" else "")))
        for key, filters in rules.items():
            targets = sorted(allowed) if key == "*" else [key]
            if key != "*" and key not in allowed:
                f.append(Finding(ERROR, "ENT-TABLE-UNKNOWN",
                                 f"principal '{principal}' has an entitlement for table '{key}' "
                                 "that is not in allowed_tables"))
            for filt in (filters or []):
                col = str(filt.get("col", "")).lower()
                if not col:
                    continue
                for tt in targets:
                    # the col must be in the column allowlist (the compiler runs an
                    # entitlement filter through the SAME _col allowlist check) ...
                    if tt in cols and col not in cols[tt]:
                        f.append(Finding(ERROR, "ENT-COL-NOTALLOWED",
                                         f"principal '{principal}' filters '{tt}.{col}' but that column "
                                         "is not in the table allowlist (queries will fail closed)"))
                    # ... and it must still exist on the real table.
                    if tt in schema and col not in schema[tt]["columns"]:
                        f.append(Finding(ERROR, "ENT-COL-MISSING",
                                         f"principal '{principal}' filters '{tt}.{col}' but that column "
                                         "no longer exists on the table (principal locked out)"))

    return f


# -- CLI -------------------------------------------------------------------

def lint(policy_path: str, schema: dict) -> tuple[int, list[Finding]]:
    policy = json.loads(Path(policy_path).read_text(encoding="utf-8"))
    findings = diff(policy, schema)
    n_err = sum(1 for x in findings if x.level == ERROR)
    return n_err, findings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="policy-schema-diff", description=__doc__.splitlines()[0])
    ap.add_argument("--policy", required=True, help="path to the policy JSON")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--schema", help="path to a schema JSON snapshot")
    src.add_argument("--hdb", help="path to a live HDB to read the schema from (needs q)")
    ap.add_argument("--json", action="store_true", help="emit findings as JSON")
    a = ap.parse_args(argv)

    if a.hdb:
        try:
            schema = schema_from_hdb(a.hdb)
        except Exception as e:
            print(f"error: could not read schema from HDB: {e}", file=sys.stderr)
            return 2
    else:
        schema = normalise_schema(json.loads(Path(a.schema).read_text(encoding="utf-8")))

    n_err, findings = lint(a.policy, schema)

    if a.json:
        print(json.dumps({"errors": n_err, "findings": [x.as_dict() for x in findings]}, indent=2))
    else:
        if not findings:
            print("OK - policy is consistent with the schema (no drift).")
        for x in findings:
            print(f"  {x}")
        n_warn = sum(1 for x in findings if x.level == WARN)
        print(f"\n{'DRIFT' if n_err else 'OK'} - {n_err} error(s), {n_warn} warning(s)")
    return 1 if n_err else 0


if __name__ == "__main__":
    sys.exit(main())
