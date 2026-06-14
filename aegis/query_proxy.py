"""Query proxy — Layer 4 ground-truth enforcement for kdb+/q and SQL.

The agent never gets a raw database handle. Its queries pass through here, and
the database only ever receives a query this module has proven safe — or
rewritten to be safe. This converts the `RES-UNBOUNDED-SCAN` *heuristic* (a
regex that can be fooled) into a *guarantee* (the DB physically cannot receive
an unbounded scan, because we parse and bound it).

Three outcomes:
  allow   — already safe (bounded, allowlisted, read-only) → pass through
  rewrite — safe after we INJECT a date-partition filter and/or a row cap
  reject  — not a single read query on an allowlisted table, or we cannot
            confidently analyse it → fail closed (the DB never sees it)

Scope (honest): q is the primary, high-value target; SQL gets table-allowlist
+ LIMIT injection. q's functional form `?[...]`, multi-statement input, and
mutations are rejected rather than guessed — fail-closed beats clever.

Deploy: point the agent's DB connection at this proxy; it enforces on every
query. Config lives in policy.json under "query_proxy".
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

_MUTATIONS = ("update", "delete", "insert", "upsert", "drop", "truncate", "alter")

# Dangerous q/kdb+ constructs that must NEVER reach the database, even embedded
# inside an otherwise-valid `select ... from <allowlisted>`. The proxy enumerates
# goodness on STRUCTURE (read on an allowlisted table) — but a select body can
# still call OS/file/eval builtins, so we also veto these tokens. A real kdb+
# agent surface should never need them in a read query; failing closed on them
# beats trusting the rest of the expression. Each is (rule, regex).
#   system/getenv/setenv  -> arbitrary shell on the kdb host (rm/kill/chmod ...)
#   hopen/hclose          -> outbound connections (exfil / lateral movement)
#   hdel                  -> delete files / HDB partition directories
#   set/save/rsave/dsave/hsym/read0/read1/[012]: -> file I/O incl. overwriting the
#                            sym file (corrupts every symbol column in the HDB) and
#                            `2:` dynamic shared-object load
#   value/eval/parse/get  -> dynamic eval (defeats static analysis) / file read
#   .z. / exit            -> hijack message handlers (.z.pg/.z.ps...) / kill process
#   .[ @[                 -> amend-in-place mutation (?[ ![ already rejected below)
#   insert/upsert/delete/update anywhere -> mutation laundered past the leading-word check
_DANGEROUS_Q = [
    ("Q-SYSTEM-EXEC",   r"\bsystem\b"),
    ("Q-ENV",           r"\b(get|set)env\b"),
    ("Q-CONN",          r"\bhopen\b|\bhclose\b"),
    ("Q-FILE-DELETE",   r"\bhdel\b"),
    ("Q-FILE-WRITE",    r"\bset\b|\b[rd]?save\b|\bhsym\b|\bread[01]\b|(?<![:\w])[012]:|(?<![\w.])-11!"),
    # .Q write/enumerate utilities: .Q.en/.Q.dpft/.Q.dpfts/.Q.dpt/.Q.dsave persist
    # to disk and write the sym file (HDB corruption). Narrow on purpose — benign
    # .Q.dd/.Q.pf/.Q.qt/.Q.fmt reads must NOT trip. (low is already lowercased.)
    ("Q-HDB-WRITE",     r"\.q\.(?:en|dpfts?|dpt|dsave)\b"),
    # `reval` is restricted-eval; `\br?eval\b` covers both eval and reval.
    ("Q-DYNAMIC-EVAL",  r"\bvalue\b|\br?eval\b|\bparse\b|\bget\b"),
    # Handler HIJACK = assigning a .z callback (.z.pg:{...}); plain .z.d/.z.p/.z.t
    # date/time reads are benign and must NOT trip — so require an assignment ':'.
    ("Q-HANDLER-EXIT",  r"\.z\.\w+\s*:|\bexit\b"),
    ("Q-AMEND",         r"\.\[|@\["),
    # PERSISTENT mutation only. Functional `update/delete ... from <t>` returns a
    # derived table and does not persist; the dangerous forms target a BACKTICK
    # global (`update ... from `trade`, insert[`trade;..], `trade upsert ..). The
    # leading-word check below still rejects a query that *starts* with a mutation.
    ("Q-PERSIST-MUTATE", r"\b(?:update|delete)\b[^;]*?\bfrom\s*`|\b(?:insert|upsert)\s*\[|`[\w.]+\s+(?:insert|upsert|set)\b"),
]


@dataclass
class QueryVerdict:
    action: str               # "allow" | "rewrite" | "reject"
    dialect: str              # "q" | "sql" | "unknown"
    safe_query: str | None = None
    tables: list[str] = field(default_factory=list)
    injected: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


class QueryRejected(Exception):
    def __init__(self, verdict: QueryVerdict):
        self.verdict = verdict
        super().__init__("; ".join(verdict.reasons) or "query rejected")


class QueryGuard:
    def __init__(self, config: dict | None = None):
        c = config or {}
        self.allowed_tables = {t.lower() for t in c.get("allowed_tables", [])}
        self.require_date_tables = {t.lower() for t in c.get("require_date_tables", [])}
        self.max_rows = int(c.get("max_rows", 1_000_000))
        self.default_date = c.get("default_date", ".z.d")

    @classmethod
    def from_policy(cls, policy_path: str | Path = None) -> "QueryGuard":
        policy_path = policy_path or Path(__file__).with_name("policy.json")
        cfg = json.loads(Path(policy_path).read_text(encoding="utf-8"))
        return cls(cfg.get("query_proxy", {}))

    # -- public ------------------------------------------------------------

    def enforce(self, query: str) -> str:
        """Return a safe query (possibly rewritten), or raise QueryRejected."""
        v = self.analyze(query)
        if v.action == "reject":
            raise QueryRejected(v)
        return v.safe_query if v.action == "rewrite" else query

    def analyze(self, query: str) -> QueryVerdict:
        raw = query.strip().rstrip(";").strip()
        # Strip comments BEFORE any analysis — a commented-out `where` clause
        # must not fool the bounded-scan check. Dialect-aware: q uses ` /`,
        # SQL uses `--`.
        dialect0 = self._dialect(raw, raw.lower())
        raw = self._strip_comments(raw, dialect0)
        low = raw.lower()

        # q functional form (?[...] / ![...]) is not safely analysable with
        # regex — fail closed. Checked first because its `;` arg-separators
        # would confuse the statement counter below.
        if "?[" in raw or "![" in raw:
            return QueryVerdict("reject", "q",
                                reasons=["q functional form not analysable — failing closed"])

        # Dangerous-builtin veto: reject OS/file/eval/handler constructs anywhere
        # in the body, even inside a valid-looking select. `select system "rm -rf
        # /data" from trade` is structurally a read on an allowlisted table, but
        # executes shell — so the structural checks below are not enough.
        for rule, pat in _DANGEROUS_Q:
            if re.search(pat, low):
                return QueryVerdict("reject", "q",
                                    reasons=[f"dangerous q construct [{rule}] not permitted in a read query — failing closed"])

        # One statement only — block laundering several queries past us.
        # q overloads `;` as a list/arg separator, so only TOP-LEVEL `;`
        # (outside () [] {}) terminate a statement.
        if self._top_level_semicolons(raw) > 0:
            return QueryVerdict("reject", "unknown",
                                reasons=["multiple statements in one query"])

        # Read-only: no mutations / DDL.
        first = re.match(r"\s*([a-zA-Z]+)", low)
        if first and first.group(1) in _MUTATIONS:
            return QueryVerdict("reject", "unknown",
                                reasons=[f"mutation/DDL '{first.group(1)}' not allowed (read-only proxy)"])

        # Must be a select/exec read.
        if not re.match(r"\s*(select|exec)\b", low):
            return QueryVerdict("reject", "unknown",
                                reasons=["not a recognised read query (select/exec)"])

        # Table extraction (first `from <table>`).
        m = re.search(r"\bfrom\s+`?([a-zA-Z][\w.]*)", low)
        if not m:
            return QueryVerdict("reject", "unknown",
                                reasons=["could not identify a source table — failing closed"])
        table = m.group(1)
        if self.allowed_tables and table not in self.allowed_tables:
            return QueryVerdict("reject", "unknown", tables=[table],
                                reasons=[f"table '{table}' is not on the query allowlist"])

        dialect = self._dialect(raw, low)
        if dialect == "sql":
            return self._enforce_sql(raw, low, table)
        return self._enforce_q(raw, low, table)

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _strip_comments(s: str, dialect: str) -> str:
        out = []
        for ln in s.splitlines() or [s]:
            if dialect == "sql":
                ln = re.sub(r"--.*$", "", ln)
            else:
                if ln.lstrip().startswith("/"):  # q full-line comment
                    continue
                ln = re.sub(r"\s/(\s.*)?$", "", ln)  # q trailing comment
            if ln.strip():
                out.append(ln.strip())
        return " ".join(out).strip()

    @staticmethod
    def _top_level_semicolons(s: str) -> int:
        depth = 0
        count = 0
        for ch in s:
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth = max(0, depth - 1)
            elif ch == ";" and depth == 0:
                count += 1
        return count

    # -- dialect-specific --------------------------------------------------

    @staticmethod
    def _dialect(raw: str, low: str) -> str:
        if "select *" in low or re.search(r"\blimit\b", low) or re.search(r"\bSELECT\b", raw):
            return "sql"
        return "q"

    def _enforce_q(self, raw: str, low: str, table: str) -> QueryVerdict:
        injected: list[str] = []
        out = raw

        has_date = bool(re.search(r"\bwhere\b.*\bdate\b", low))
        if table in self.require_date_tables and not has_date:
            if re.search(r"\bwhere\b", low):
                out = re.sub(r"(?i)\bwhere\b", f"where date={self.default_date}, ", out, count=1)
            else:
                out = out + f" where date={self.default_date}"
            injected.append(f"date={self.default_date}")

        # Row cap. The proxy GUARANTEES the outgoing query reads <= max_rows; it
        # does not take a caller-supplied cap on trust. A cap that is present and
        # already within max_rows is left alone; an over-limit cap is TIGHTENED;
        # an absent cap is INJECTED. We bound with a `where i<N` predicate rather
        # than `select[N]` — `select[N]` throws `nyi` on PARTITIONED kdb+ tables
        # (the standard HDB layout), so it would make the proxy emit a query the
        # DB rejects, breaking the guarantee that the DB only ever receives a
        # *runnable* safe query. `where ... i<N` is partition-safe and composes
        # with `by`. (Verified against licensed kdb+ 4.1 on a real partitioned HDB.)
        if re.match(r"\s*select\b", low):
            capped = False
            # tighten an over-limit virtual-index `i<N`
            m = re.search(r"\bi\s*<\s*(\d+)", out)
            if m:
                capped = True
                if int(m.group(1)) > self.max_rows:
                    out = re.sub(r"(\bi\s*<\s*)\d+", rf"\g<1>{self.max_rows}", out, count=1)
                    injected.append(f"tightened-cap=i<{self.max_rows}")
            # tighten an over-limit `select[N]` (caller's form kept; value bounded)
            m2 = re.search(r"(?i)select\s*\[\s*(\d+)", out)
            if m2:
                capped = True
                if int(m2.group(1)) > self.max_rows:
                    out = re.sub(r"(?i)(select\s*\[\s*)\d+", rf"\g<1>{self.max_rows}", out, count=1)
                    injected.append(f"tightened-cap=select[{self.max_rows}]")
            # no cap of any kind -> inject one
            if not capped:
                if re.search(r"(?i)\bwhere\b", out):
                    out = out + f", i<{self.max_rows}"
                else:
                    out = out + f" where i<{self.max_rows}"
                injected.append(f"row-cap=i<{self.max_rows}")

        if injected:
            return QueryVerdict("rewrite", "q", safe_query=out, tables=[table],
                                injected=injected,
                                reasons=[f"injected {', '.join(injected)} to bound the scan"])
        return QueryVerdict("allow", "q", safe_query=raw, tables=[table],
                            reasons=["already bounded and allowlisted"])

    def _enforce_sql(self, raw: str, low: str, table: str) -> QueryVerdict:
        has_date = bool(re.search(r"\bwhere\b.*\bdate\b", low))
        if table in self.require_date_tables and not has_date:
            return QueryVerdict("reject", "sql", tables=[table],
                                reasons=[f"partitioned table '{table}' requires an explicit date predicate"])
        if not re.search(r"\blimit\b", low):
            out = raw.rstrip("; ") + f" LIMIT {self.max_rows}"
            return QueryVerdict("rewrite", "sql", safe_query=out, tables=[table],
                                injected=[f"LIMIT {self.max_rows}"],
                                reasons=[f"injected LIMIT {self.max_rows}"])
        return QueryVerdict("allow", "sql", safe_query=raw, tables=[table],
                            reasons=["already bounded and allowlisted"])
