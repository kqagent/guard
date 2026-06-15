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
# Allowlisted binary operators for the bounded expression AST -> q operators.
_EXPR_OPS = {"add": "+", "sub": "-", "mul": "*", "div": "%"}
# Allowlisted monadic running/window functions (each returns a column, bounded
# by the same scan cap as the underlying select).
_WIN_FNS = {"sums", "maxs", "mins", "prds", "deltas", "ratios", "reverse"}
# Monadic aggregations usable inside an expression node (dyadic wavg/wsum stay in
# the `aggs` field). `countdistinct` is a named convenience for `count distinct`.
_EXPR_AGGS = {"avg", "sum", "min", "max", "count", "first", "last",
              "dev", "var", "med", "countdistinct", "wavg", "wsum"}
_MAX_EXPR_DEPTH = 6  # bound recursion; a desk expression is never deeper
_MAX_CLAUSE_ITEMS = 64  # cap select/agg/filter/by list lengths — a real desk
                        # query never has this many, and it stops a giant request
                        # expanding into a huge compiled query (resource guard).


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
        # Raw-select date-range cap: a raw row-listing whose date range spans more
        # than this many partitions is rejected (bounds materialisation globally,
        # since a raw listing materialises up to max_rows per partition). Reducing
        # queries are unaffected. 0/absent => no span cap.
        self.max_partition_span = int(c.get("max_partition_span", 0) or 0)
        # Row-level entitlements (mandatory, non-removable per-principal row filter).
        # mode: "open" (default — absence means no row filter) or "default_deny"
        # (a principal with no entry for a queried table is rejected — sees nothing).
        ent = c.get("entitlements") or {}
        self.ent_mode = ent.get("mode", "open")
        # {principal -> {table-or-"*" -> [filter-dict, ...]}}; table keys lowercased.
        self.ent_principals = {
            p: {(t.lower() if t != "*" else "*"): fs for t, fs in (rule.get("row_filters") or {}).items()}
            for p, rule in (ent.get("principals") or {}).items()
        }

    @classmethod
    def from_policy(cls, policy_path: str | Path = None) -> "QueryCompiler":
        policy_path = policy_path or Path(__file__).with_name("policy.json")
        cfg = json.loads(Path(policy_path).read_text(encoding="utf-8"))
        qp = dict(cfg.get("query_proxy", {}))
        if "entitlements" in cfg:          # entitlements is a top-level policy block
            qp["entitlements"] = cfg["entitlements"]
        return cls(qp)

    # -- public ------------------------------------------------------------

    def compile(self, request: dict, principal: str | None = None) -> str:
        """Compile a structured request to safe bounded q, or raise.

        `principal` is the authenticated identity from the PDP/action — the agent
        cannot set it. Under row-level entitlements it selects the mandatory,
        non-removable row filter ANDed into every table reference."""
        if not isinstance(request, dict):
            raise StructuredQueryRejected("request must be an object")
        if "join" in request:
            out = self._compile_join(request["join"], principal)
        elif "setop" in request:
            out = self._compile_setop(request, principal)
        else:
            out = self._compile_select(request, principal)
        return self._backstop(out)

    # -- validation helpers ------------------------------------------------

    def _reject(self, msg: str):
        raise StructuredQueryRejected(msg)

    def _list(self, v, what: str) -> list:
        """Validate a clause list and bound its length (resource guard)."""
        if not isinstance(v, list):
            self._reject(f"{what} must be a list")
        if len(v) > _MAX_CLAUSE_ITEMS:
            self._reject(f"{what} has {len(v)} items (max {_MAX_CLAUSE_ITEMS}) — failing closed")
        return v

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
            import math
            if not math.isfinite(v):   # json.loads accepts Infinity/NaN by default
                self._reject(f"non-finite numeric value not allowed: {v!r}")
            return repr(v)
        if isinstance(v, str):
            if _DATE.match(v):
                return v
            if _SYM.match(v):
                return "`" + v
            self._reject(f"unsafe string value: {v!r}")
        self._reject(f"unsupported value type: {type(v).__name__}")

    def _expr(self, node, cols_allowed: set, depth: int = 0) -> str:
        """Compile a bounded expression-AST node to q. A node is exactly one of:
        {col}, {lit}, {op,args:[expr,expr]}, {agg,arg?}, {win,arg}. Every leaf goes
        through the column/scalar allowlist machinery; operators/aggs/windows are
        allowlisted; there is no free-form string anywhere — so an expression can
        compute (bid+ask)%2 or sums size but cannot name an un-vetted column or
        inject a token."""
        if depth > _MAX_EXPR_DEPTH:
            self._reject("expression too deeply nested")
        if not isinstance(node, dict):
            self._reject(f"expression node must be an object, got {type(node).__name__}")
        keys = {"col", "lit", "op", "agg", "win"} & set(node)
        if len(keys) != 1:
            self._reject(f"expression node must have exactly one of col/lit/op/agg/win: {node!r}")
        if "col" in node:
            return self._col(node["col"], cols_allowed)
        if "lit" in node:
            return self._scalar(node["lit"])
        if "op" in node:
            if node["op"] not in _EXPR_OPS:
                self._reject(f"operator '{node['op']}' not allowed")
            args = node.get("args")
            if not isinstance(args, list) or len(args) != 2:
                self._reject("op requires exactly 2 args")
            a = self._expr(args[0], cols_allowed, depth + 1)
            b = self._expr(args[1], cols_allowed, depth + 1)
            return f"({a}{_EXPR_OPS[node['op']]}{b})"
        if "win" in node:
            if node["win"] not in _WIN_FNS:
                self._reject(f"window function '{node['win']}' not allowed")
            return f"{node['win']} {self._expr(node['arg'], cols_allowed, depth + 1)}"
        # agg
        fn = node["agg"]
        if fn not in _EXPR_AGGS:
            self._reject(f"aggregation '{fn}' not allowed in expression")
        if fn == "countdistinct":
            return f"count distinct {self._expr(node['arg'], cols_allowed, depth + 1)}"
        if fn == "count" and node.get("arg") is None:
            return "count i"
        if fn in ("wavg", "wsum"):                 # dyadic: `weight wavg arg`
            w = node.get("weight")
            if w is None:
                self._reject(f"'{fn}' in an expression requires a 'weight' expr (e.g. TWAP weights deltas time)")
            return f"({self._expr(w, cols_allowed, depth + 1)}) {fn} ({self._expr(node['arg'], cols_allowed, depth + 1)})"
        return f"{fn} {self._expr(node['arg'], cols_allowed, depth + 1)}"

    def _select_list(self, req: dict, cols_allowed: set):
        """Optional `select`: [{as, expr}] — named computed/aggregated expressions.
        Returns (compiled_str_or_None, set_of_aliases)."""
        sel = req.get("select")
        if not sel:
            return None, set()
        self._list(sel, "select")
        parts, aliases = [], set()
        for item in sel:
            if not isinstance(item, dict) or "expr" not in item or "as" not in item:
                self._reject("each select item needs 'as' and 'expr'")
            alias = item["as"]
            if not _IDENT.match(str(alias)):
                self._reject(f"invalid select alias: {alias!r}")
            parts.append(f"{alias}:{self._expr(item['expr'], cols_allowed)}")
            aliases.add(str(alias).lower())
        return ", ".join(parts), aliases

    # -- clause builders ---------------------------------------------------

    def _select_expr(self, req: dict, cols_allowed: set) -> str:
        aggs = req.get("aggs")
        if aggs:
            self._list(aggs, "aggs")
            parts = []
            for a in aggs:
                if not isinstance(a, dict):
                    self._reject("each agg must be an object")
                fn = a.get("fn")
                if fn not in self.agg_fns and fn != "countdistinct":
                    self._reject(f"aggregation '{fn}' not on the allowlist")
                col = self._col(a["col"], cols_allowed) if a.get("col") is not None else None
                weight = self._col(a["weight"], cols_allowed) if a.get("weight") is not None else None
                if fn in ("wavg", "wsum"):              # dyadic: `weight wavg col`
                    if not (col and weight):
                        self._reject(f"'{fn}' requires both 'col' and 'weight' (e.g. size-weighted price)")
                    body = f"{weight} {fn} {col}"
                elif fn == "countdistinct":
                    if not col:
                        self._reject("countdistinct requires 'col'")
                    body = f"count distinct {col}"
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
            self._list(columns, "columns")
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
        for c in self._list(req.get("by", []) or [], "by"):
            clauses.append(self._col(c, cols_allowed))
        return (" by " + ", ".join(clauses)) if clauses else ""

    def _filter_pred(self, f: dict, cols_allowed: set) -> str:
        """Compile ONE structured filter to a q predicate. Column goes through the
        allowlist (`_col`); values through the injection-safe scalar path
        (`_scalar`). Used for BOTH the agent's own filters and the mandatory
        entitlement filters — so an entitlement value can no more inject than a
        user value can."""
        if not isinstance(f, dict):
            self._reject("each filter must be an object")
        col = self._col(f.get("col"), cols_allowed)
        op = f.get("op")
        if op not in _FILTER_OPS:
            self._reject(f"filter op '{op}' not allowed")
        val = f.get("value")
        if op in _SCALAR_OPS:
            return f"{col}{op}{self._scalar(val)}"
        if op == "in":
            if not isinstance(val, list) or not val:
                self._reject("'in' requires a non-empty list")
            items = [self._scalar(v) for v in val]
            # symbols concat without separators (`A`B); others use (a;b)
            return f"{col} in {''.join(items)}" if all(s.startswith("`") for s in items) \
                else f"{col} in ({';'.join(items)})"
        if op == "within":
            if not isinstance(val, list) or len(val) != 2:
                self._reject("'within' requires [lo, hi]")
            return f"{col} within ({self._scalar(val[0])};{self._scalar(val[1])})"
        if op == "like":
            if not isinstance(val, str) or not _LIKE.match(val):
                self._reject(f"unsafe like pattern: {val!r}")
            return f'{col} like "{val}"'
        self._reject(f"filter op '{op}' not allowed")

    def _entitlement_gate(self, principal, table: str) -> None:
        """Fail-closed membership check, no predicate compilation. Under
        default_deny a principal must have SOME entitlement (a '*' baseline or a
        table-specific entry) for the table, else the query is denied. Used both
        before compiling row predicates and to gate `meta` (which returns no rows
        but must still respect default-deny)."""
        if self.ent_mode != "default_deny":
            return
        rule = self.ent_principals.get(principal)
        if rule is None:
            self._reject(f"principal {principal!r} has no row entitlements (default-deny) - denied")
        if rule.get("*") is None and rule.get(table.lower()) is None:
            self._reject(f"principal {principal!r} has no row entitlement for table '{table}' (default-deny) - denied")

    def _entitlement_preds(self, principal, table: str, cols_allowed: set) -> list[str]:
        """MANDATORY per-principal row filter for `table`. Returns predicate
        strings to be ANDed (non-removably) into the WHERE clause of EVERY table
        reference. The agent cannot set `principal`, cannot remove these, and
        cannot widen past them (they AND with its own filters -> intersection).
        Fail-closed under default_deny; no-op under open mode (default).

        FAIL-SAFE COMBINE: a '*' baseline and a table-specific entry are BOTH
        applied (ANDed), not replace-one-with-the-other. So a global restriction
        (e.g. region) is never silently dropped for a table that also has a
        column-specific rule - forgetting can only over-restrict, never widen."""
        if self.ent_mode != "default_deny" and not self.ent_principals:
            return []   # entitlements not configured -> no row filter (back-compat)
        self._entitlement_gate(principal, table)
        rule = self.ent_principals.get(principal)
        if rule is None:
            return []   # open mode, unknown principal -> no row filter
        filters = []
        if rule.get("*") is not None:                      # global baseline (always applies)
            filters += self._list(rule["*"], "entitlement row_filters")
        if rule.get(table.lower()) is not None:            # plus table-specific (ANDed)
            filters += self._list(rule[table.lower()], "entitlement row_filters")
        # Compile each entitlement filter through the SAME injection-safe path.
        return [self._filter_pred(f, cols_allowed) for f in filters]

    def _where_expr(self, req: dict, table: str, cols_allowed: set, principal=None) -> str:
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

        # structured filters (the agent's own)
        for f in self._list(req.get("filters", []) or [], "filters"):
            preds.append(self._filter_pred(f, cols_allowed))

        # MANDATORY row-level entitlement predicate(s) — ANDed in, non-removable.
        # Injected for EVERY table reference (this method is the single chokepoint
        # for top-level selects AND both sides of joins/setops), so the agent can
        # never reach a row outside its set, including via a join, setop, computed
        # column, or a contradictory filter of its own (predicates AND -> intersection).
        preds.extend(self._entitlement_preds(principal, table, cols_allowed))

        # MATERIALISATION bound, shape-aware. A `where ..., i<N` bounds the rows the
        # select reads off disk — but it CORRUPTS a reducing query (count/sum/avg/
        # grouped/distinct see only the first N rows; found at 500M scale: `count`
        # returned the cap 1e6, not 1e7). And `N sublist (select ...)` does NOT bound
        # materialisation — proven on real kdb+: it reads the whole match (same space
        # as the uncapped select) then takes N. So:
        #   * RAW row-listing  -> apply `i<N` here: bounds what's read AND is the
        #     correct first-N semantics. Without it, one date partition (tens of
        #     millions of rows at scale) is fully materialised on the gateway per
        #     query — a resource/DoS vector the `N sublist` result-cap does not stop.
        #   * REDUCING query (aggs/by/distinct/agg-expr) -> NO `i<N` (would corrupt);
        #     it must read its input, bounded to one partition by the date filter,
        #     and its small result is capped by `N sublist` in _compile_select.
        if not self._reduces(req):
            preds.append(f"i<{self.max_rows}")
        return (" where " + ", ".join(preds)) if preds else ""

    @staticmethod
    def _expr_has_agg(node) -> bool:
        """True if a select-expr AST contains an aggregation node (so the query
        reduces and a row-scan cap would corrupt it)."""
        if not isinstance(node, dict):
            return False
        if "agg" in node:
            return True
        if "op" in node:
            args = node.get("args")
            return isinstance(args, list) and any(QueryCompiler._expr_has_agg(a) for a in args)
        if "win" in node:
            return QueryCompiler._expr_has_agg(node.get("arg"))
        return False

    def _reduces(self, req: dict) -> bool:
        """Does this query reduce its input (aggregate / group / distinct)?
        If so, an `i<N` scan cap would give a wrong answer and must be omitted."""
        if req.get("aggs") or req.get("by") or req.get("distinct"):
            return True
        for item in (req.get("select") or []):
            if isinstance(item, dict) and self._expr_has_agg(item.get("expr")):
                return True
        return False

    # -- top-level forms ---------------------------------------------------

    def _alias_set(self, req: dict) -> set:
        """Identifiers that exist in the RESULT (so sort may reference them):
        aggs[].as, select[].as, bucket.as."""
        out = set()
        for a in req.get("aggs", []) or []:
            if isinstance(a, dict) and a.get("as") and _IDENT.match(str(a["as"])):
                out.add(str(a["as"]).lower())
        for s in req.get("select", []) or []:
            if isinstance(s, dict) and s.get("as") and _IDENT.match(str(s["as"])):
                out.add(str(s["as"]).lower())
        b = req.get("bucket")
        if isinstance(b, dict) and b.get("as") and _IDENT.match(str(b["as"])):
            out.add(str(b["as"]).lower())
        return out

    def _max_span_check(self, req: dict, table: str) -> None:
        """Raw-select date-range cap: a RAW row-listing whose date range spans more
        than max_partition_span days is rejected — bounds materialisation globally
        (a raw listing reads up to max_rows PER partition). Reducing queries
        (aggs/by/distinct) are exempt: they must read their input and their result
        is already result-capped."""
        if not self.max_partition_span or self._reduces(req):
            return
        date = req.get("date")
        if not isinstance(date, dict):
            return
        d_from, d_to = date.get("from"), date.get("to")
        if not (d_from and d_to) or not (_DATE.match(d_from) and _DATE.match(d_to)):
            return
        from datetime import date as _d
        span = (_d(*map(int, d_to.split("."))) - _d(*map(int, d_from.split("."))))
        if span.days + 1 > self.max_partition_span:
            self._reject(f"raw row-listing date range spans {span.days + 1} days "
                         f"(max {self.max_partition_span}) — narrow the range or use an aggregation")

    def _compile_select(self, req: dict, principal=None) -> str:
        table = self._table(req.get("table"))
        if req.get("op") == "meta":
            self._entitlement_gate(principal, table)   # meta returns no rows but still honours default-deny
            return f"meta {table}"
        cols_allowed = self._cols_for(table)
        self._max_span_check(req, table)
        sel_list, _ = self._select_list(req, cols_allowed)
        sel = sel_list if sel_list is not None else self._select_expr(req, cols_allowed)
        distinct = "distinct " if req.get("distinct") else ""
        by = self._by_expr(req, cols_allowed)
        where = self._where_expr(req, table, cols_allowed, principal)
        base = f"select {distinct}{sel}{by} from {table}{where}".replace("select  ", "select ")

        # Result shaping: optional sort + top/first-N, applied OUTSIDE the scan.
        # `N sublist` (not `N#`) so an N larger than the row count never wraps.
        sort = req.get("sort")
        if sort is not None:
            if not isinstance(sort, dict):
                self._reject("sort must be an object {col,dir}")
            sname = sort.get("col")
            aliases = self._alias_set(req)   # sort may target a computed result column
            if not (isinstance(sname, str) and _IDENT.match(sname)
                    and (sname.lower() in cols_allowed or sname.lower() in aliases)):
                self._reject(f"sort column '{sname}' is neither an allowlisted column nor a result alias")
            scol = sname
            direction = sort.get("dir", "asc")
            if direction not in ("asc", "desc"):
                self._reject(f"sort dir must be asc/desc, got {direction!r}")
            xf = "xdesc" if direction == "desc" else "xasc"
            base = f"`{scol} {xf} ({base})"
        # RESULT-row cap (always): `N sublist` the final result — bounds the rows
        # returned to the agent WITHOUT corrupting any aggregation (sublist takes
        # the first N of the RESULT, after grouping/aggregation). An explicit
        # caller limit is honoured but never allowed to exceed max_rows.
        limit = req.get("limit")
        if limit is not None and (not isinstance(limit, int) or limit <= 0):
            self._reject(f"invalid limit: {limit!r}")
        eff = min(limit, self.max_rows) if isinstance(limit, int) else self.max_rows
        wrapped = base if base.startswith("`") else f"({base})"  # sort already parenthesised
        return f"{eff} sublist {wrapped}"

    def _compile_setop(self, req: dict, principal=None) -> str:
        op = req.get("setop")
        if op not in ("except", "union", "inter"):
            self._reject(f"setop '{op}' not supported (except/union/inter)")
        left, right = req.get("left"), req.get("right")
        if not isinstance(left, dict) or not isinstance(right, dict):
            self._reject("setop requires 'left' and 'right' structured requests")
        # Each side compiled via _compile_select -> carries ITS table's entitlement.
        return f"({self._compile_select(left, principal)}) {op} ({self._compile_select(right, principal)})"

    def _compile_join(self, join: dict, principal=None) -> str:
        if not isinstance(join, dict):
            self._reject("join must be an object")
        jtype = join.get("type")
        if jtype not in ("asof", "left"):
            self._reject(f"join type '{jtype}' not supported (asof|left)")
        on = join.get("on")
        if not isinstance(on, list) or not on or not all(isinstance(c, str) and _IDENT.match(c) for c in on):
            self._reject("join 'on' must be a list of column identifiers")
        left, right = join.get("left"), join.get("right")
        if not isinstance(left, dict) or not isinstance(right, dict):
            self._reject("join requires 'left' and 'right' structured requests")
        lcols = self._cols_for(self._table(left.get("table")))
        rcols = self._cols_for(self._table(right.get("table")))
        for c in on:                       # join keys must be allowlisted on BOTH tables
            if c.lower() not in lcols or c.lower() not in rcols:
                self._reject(f"join key '{c}' not allowlisted on both tables")
        # Each side compiled via _compile_select -> carries ITS table's entitlement
        # predicate, so a join can never surface a row either side isn't entitled to.
        lsel = self._compile_select(left, principal)
        rsel = self._compile_select(right, principal)
        keys = "".join("`" + c for c in on)

        if jtype == "left":
            # cross-table comparison: (keyed select) lj (keyed select). Both sides
            # must group by the join key(s) so q has a keyed table to join on.
            for nm, side in (("left", left), ("right", right)):
                by = [b.lower() for b in (side.get("by") or [])]
                if not all(c.lower() in by for c in on):
                    self._reject(f"left-join {nm} side must 'by' the join key(s) {on} (keyed table)")
            return f"({lsel}) lj ({rsel})"

        # asof (aj). Optionally compute over the join RESULT (cols = union of both
        # tables' allowlists), e.g. effective spread = price-(bid+ask)%2.
        inner = f"aj[{keys}; {lsel}; {rsel}]"
        sel = join.get("select")
        if sel:
            sel_str, _ = self._select_list({"select": sel}, lcols | rcols)
            return f"select {sel_str} from {inner}"
        return inner

    # -- backstop ----------------------------------------------------------

    def _backstop(self, out: str) -> str:
        low = out.lower()
        for rule, pat in _DANGEROUS_Q:
            if re.search(pat, low):
                self._reject(f"compiled output tripped deny-list backstop [{rule}] "
                             f"— compiler bug, failing closed")
        return out
