"""Structured query compiler — the query plane done right (enumerate goodness).

The agent never sends q. It sends a *structured request* (data, not code) and
this module COMPILES it into safe, bounded q. There is no free-form q to escape,
so the injection surface and the free-form proxy's coverage gap disappear
together. Every field is validated against an allowlist before compilation;
anything off-list is rejected, fail-closed. The compiler can only emit
`select`/`exec`/`meta` over allowlisted tables — `system`, `hopen`, `set`,
`value`, `.z.*`, `.Q.*`, `-N!`, amend and mutation have no slot in the grammar.

As belt-and-braces, the compiled output is run past the `_DANGEROUS_Q` deny-list
(the free-form proxy's backstop): if a validated request ever compiled to a
dangerous token it is a compiler bug, and we fail closed rather than emit it.

Pure/stdlib/testable. Reuses the date-filter + row-cap guarantees of the proxy.

Request shape (all keys optional unless noted):
    {"table": "trade",                    # REQUIRED, ∈ allowed_tables
     "op": "meta",                        # optional: "meta" -> `meta <table>`
     "columns": ["sym","price"],          # ∈ per-table column allowlist
     "aggs": [{"fn":"avg","col":"price","as":"vwap"}],  # fn ∈ agg allowlist
     "by": ["sym"],                       # grouping cols (allowlisted)
     "bucket": {"col":"time","size":"00:05","as":"bar"},# xbar time bars
     "date": {"from":"2015.01.07","to":"2015.01.08"},   # required if partitioned
     "filters": [{"col":"sym","op":"in","value":["AAPL","MSFT"]},
                 {"col":"price","op":">","value":100}],
     "limit": 100000,                     # capped at max_rows
     "join": {"type":"asof","on":["sym","time"],          # asof (aj) join of
              "left":{...request...}, "right":{...request...}}}
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .query_proxy import _DANGEROUS_Q

_IDENT = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*$")        # column / table identifiers
_DATE = re.compile(r"^\d{4}\.\d{2}\.\d{2}$")            # q date literal
_SYM = re.compile(r"^[A-Za-z0-9_.\-]+$")                # safe symbol chars (no `, space, q metachars)
_LIKE = re.compile(r"^[A-Za-z0-9_.\-*? ]+$")            # safe like-pattern charset
_TIMESPAN = re.compile(r"^\d{1,2}:\d{2}(:\d{2}(\.\d+)?)?$")  # 00:05, 01:00:00
_SCALAR_OPS = {"=", "<", ">", "<=", ">="}
_FILTER_OPS = _SCALAR_OPS | {"in", "within", "like"}
_DEFAULT_AGGS = {"avg", "sum", "min", "max", "count", "first", "last",
                 "wavg", "dev", "var", "med", "cor", "wsum"}


class StructuredQueryRejected(Exception):
    """A structured request failed validation — the compiler emits nothing."""


class QueryCompiler:
    def __init__(self, config: dict | None = None):
        c = config or {}
        self.allowed_tables = {t.lower() for t in c.get("allowed_tables", [])}
        self.require_date_tables = {t.lower() for t in c.get("require_date_tables", [])}
        self.max_rows = int(c.get("max_rows", 1_000_000))
        # Per-table column allowlist (new). Without it, no columns can be named.
        self.columns = {k.lower(): {col.lower() for col in v}
                        for k, v in c.get("columns", {}).items()}
        self.agg_fns = set(c.get("agg_fns", _DEFAULT_AGGS))

    @classmethod
    def from_policy(cls, policy_path: str | Path = None) -> "QueryCompiler":
        policy_path = policy_path or Path(__file__).with_name("policy.json")
        cfg = json.loads(Path(policy_path).read_text(encoding="utf-8"))
        return cls(cfg.get("query_proxy", {}))

    # -- public ------------------------------------------------------------

    def compile(self, request: dict) -> str:
        """Compile a structured request to safe bounded q, or raise."""
        if not isinstance(request, dict):
            raise StructuredQueryRejected("request must be an object")
        if "join" in request:
            out = self._compile_join(request["join"])
        else:
            out = self._compile_select(request)
        return self._backstop(out)

    # -- validation helpers ------------------------------------------------

    def _reject(self, msg: str):
        raise StructuredQueryRejected(msg)

    def _table(self, table) -> str:
        if not isinstance(table, str) or not _IDENT.match(table):
            self._reject(f"invalid table identifier: {table!r}")
        if self.allowed_tables and table.lower() not in self.allowed_tables:
            self._reject(f"table '{table}' not on the query allowlist")
        return table

    def _cols_for(self, table: str) -> set:
        cols = self.columns.get(table.lower())
        if not cols:
            self._reject(f"no column allowlist configured for table '{table}' — failing closed")
        return cols

    def _col(self, name, cols_allowed: set) -> str:
        if not isinstance(name, str) or not _IDENT.match(name):
            self._reject(f"invalid column identifier: {name!r}")
        if name.lower() not in cols_allowed:
            self._reject(f"column '{name}' not on the allowlist for this table")
        return name

    def _scalar(self, v) -> str:
        """Re-serialise a typed literal to q. Never interpolates caller text."""
        if isinstance(v, bool):
            return "1b" if v else "0b"
        if isinstance(v, int):
            return str(v)
        if isinstance(v, float):
            return repr(v)
        if isinstance(v, str):
            if _DATE.match(v):
                return v
            if _SYM.match(v):
                return "`" + v
            self._reject(f"unsafe string value: {v!r}")
        self._reject(f"unsupported value type: {type(v).__name__}")

    # -- clause builders ---------------------------------------------------

    def _select_expr(self, req: dict, cols_allowed: set) -> str:
        aggs = req.get("aggs")
        if aggs:
            if not isinstance(aggs, list):
                self._reject("aggs must be a list")
            parts = []
            for a in aggs:
                if not isinstance(a, dict):
                    self._reject("each agg must be an object")
                fn = a.get("fn")
                if fn not in self.agg_fns:
                    self._reject(f"aggregation '{fn}' not on the allowlist")
                col = self._col(a["col"], cols_allowed) if a.get("col") is not None else None
                weight = self._col(a["weight"], cols_allowed) if a.get("weight") is not None else None
                if fn in ("wavg", "wsum"):              # dyadic: `weight wavg col`
                    if not (col and weight):
                        self._reject(f"'{fn}' requires both 'col' and 'weight' (e.g. size-weighted price)")
                    body = f"{weight} {fn} {col}"
                elif fn == "count":
                    body = f"count {col}" if col else "count i"
                else:                                   # monadic: `avg price`
                    if not col:
                        self._reject(f"aggregation '{fn}' requires 'col'")
                    body = f"{fn} {col}"
                alias = a.get("as")
                if alias is not None:
                    if not _IDENT.match(str(alias)):
                        self._reject(f"invalid agg alias: {alias!r}")
                    body = f"{alias}:{body}"
                parts.append(body)
            return ", ".join(parts)
        columns = req.get("columns")
        if columns:
            if not isinstance(columns, list):
                self._reject("columns must be a list")
            return ", ".join(self._col(c, cols_allowed) for c in columns)
        return ""  # select all columns

    def _by_expr(self, req: dict, cols_allowed: set) -> str:
        clauses = []
        bucket = req.get("bucket")
        if bucket:
            if not isinstance(bucket, dict):
                self._reject("bucket must be an object")
            bcol = self._col(bucket["col"], cols_allowed)
            size = bucket.get("size")
            if not isinstance(size, str) or not _TIMESPAN.match(size):
                self._reject(f"invalid bucket size (expect HH:MM[:SS]): {size!r}")
            alias = bucket.get("as", bcol)
            if not _IDENT.match(str(alias)):
                self._reject(f"invalid bucket alias: {alias!r}")
            # bucket a TIMESTAMP column by a timespan: `0D00:05 xbar time`
            # (a bare `00:05` is a minute type and `type`-errors against a timestamp).
            clauses.append(f"{alias}:0D{size} xbar {bcol}")
        for c in req.get("by", []) or []:
            clauses.append(self._col(c, cols_allowed))
        return (" by " + ", ".join(clauses)) if clauses else ""

    def _where_expr(self, req: dict, table: str, cols_allowed: set) -> str:
        preds = []
        # date predicate (required for partitioned tables)
        date = req.get("date")
        if date is not None:
            if not isinstance(date, dict):
                self._reject("date must be an object {from,to}")
            d_from, d_to = date.get("from"), date.get("to")
            for d in (d_from, d_to):
                if d is not None and not (isinstance(d, str) and _DATE.match(d)):
                    self._reject(f"invalid date literal: {d!r}")
            if d_from and d_to and d_from != d_to:
                preds.append(f"date within {d_from} {d_to}")
            elif d_from or d_to:
                preds.append(f"date={d_from or d_to}")
        elif table.lower() in self.require_date_tables:
            self._reject(f"table '{table}' is partitioned — a date range is required")

        # structured filters
        for f in req.get("filters", []) or []:
            if not isinstance(f, dict):
                self._reject("each filter must be an object")
            col = self._col(f.get("col"), cols_allowed)
            op = f.get("op")
            if op not in _FILTER_OPS:
                self._reject(f"filter op '{op}' not allowed")
            val = f.get("value")
            if op in _SCALAR_OPS:
                preds.append(f"{col}{op}{self._scalar(val)}")
            elif op == "in":
                if not isinstance(val, list) or not val:
                    self._reject("'in' requires a non-empty list")
                items = [self._scalar(v) for v in val]
                # symbols concat without separators (`A`B); others use (a;b)
                if all(s.startswith("`") for s in items):
                    preds.append(f"{col} in {''.join(items)}")
                else:
                    preds.append(f"{col} in ({';'.join(items)})")
            elif op == "within":
                if not isinstance(val, list) or len(val) != 2:
                    self._reject("'within' requires [lo, hi]")
                lo, hi = self._scalar(val[0]), self._scalar(val[1])
                preds.append(f"{col} within ({lo};{hi})")
            elif op == "like":
                if not isinstance(val, str) or not _LIKE.match(val):
                    self._reject(f"unsafe like pattern: {val!r}")
                preds.append(f'{col} like "{val}"')

        # SCAN cap (always) — partition-safe `i<max_rows`. This bounds rows READ
        # from disk (resource protection). The RESULT-shaping `limit` is applied
        # separately, wrap-safely, via `sublist` in _compile_select.
        preds.append(f"i<{self.max_rows}")
        return " where " + ", ".join(preds)

    # -- top-level forms ---------------------------------------------------

    def _compile_select(self, req: dict) -> str:
        table = self._table(req.get("table"))
        if req.get("op") == "meta":
            return f"meta {table}"
        cols_allowed = self._cols_for(table)
        sel = self._select_expr(req, cols_allowed)
        distinct = "distinct " if req.get("distinct") else ""
        by = self._by_expr(req, cols_allowed)
        where = self._where_expr(req, table, cols_allowed)
        base = f"select {distinct}{sel}{by} from {table}{where}".replace("select  ", "select ")

        # Result shaping: optional sort + top/first-N, applied OUTSIDE the scan.
        # `N sublist` (not `N#`) so an N larger than the row count never wraps.
        sort = req.get("sort")
        if sort is not None:
            if not isinstance(sort, dict):
                self._reject("sort must be an object {col,dir}")
            scol = self._col(sort.get("col"), cols_allowed)
            direction = sort.get("dir", "asc")
            if direction not in ("asc", "desc"):
                self._reject(f"sort dir must be asc/desc, got {direction!r}")
            xf = "xdesc" if direction == "desc" else "xasc"
            base = f"`{scol} {xf} ({base})"
        limit = req.get("limit")
        if limit is not None:
            if not isinstance(limit, int) or limit <= 0:
                self._reject(f"invalid limit: {limit!r}")
            base = f"{min(limit, self.max_rows)} sublist {base if sort is not None else '(' + base + ')'}"
        return base

    def _compile_join(self, join: dict) -> str:
        if not isinstance(join, dict):
            self._reject("join must be an object")
        if join.get("type") != "asof":
            self._reject(f"join type '{join.get('type')}' not supported (asof only)")
        on = join.get("on")
        if not isinstance(on, list) or not on or not all(isinstance(c, str) and _IDENT.match(c) for c in on):
            self._reject("asof 'on' must be a list of column identifiers")
        left, right = join.get("left"), join.get("right")
        if not isinstance(left, dict) or not isinstance(right, dict):
            self._reject("asof join requires 'left' and 'right' structured requests")
        # validate the join keys against BOTH tables' column allowlists
        for side in (left, right):
            cols = self._cols_for(self._table(side.get("table")))
            for c in on:
                if c.lower() not in cols:
                    self._reject(f"join key '{c}' not allowlisted on table '{side.get('table')}'")
        lsel = self._compile_select(left)
        rsel = self._compile_select(right)
        keys = "".join("`" + c for c in on)
        return f"aj[{keys}; {lsel}; {rsel}]"

    # -- backstop ----------------------------------------------------------

    def _backstop(self, out: str) -> str:
        low = out.lower()
        for rule, pat in _DANGEROUS_Q:
            if re.search(pat, low):
                self._reject(f"compiled output tripped deny-list backstop [{rule}] "
                             f"— compiler bug, failing closed")
        return out
