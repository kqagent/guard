"""Free-form q, governed by allowlist-on-parse (not denylist-on-text).

The structured path is safe by construction. But a real investigation sometimes
needs hand-written q the structured form can't express. Scanning that text for
"bad" patterns is a losing arms race (q can build `system` at runtime, obfuscate,
etc.). So we do the opposite, the same way the rest of Aegis does: **enumerate
goodness.**

The mechanism, and why it is safe:
  1. PARSE the free-form q into tokens, then LIFT it into a *structured request*
     (the same dict the QueryCompiler consumes). The lifter only knows the safe
     subset (select/exec/meta, where, by, allowlisted aggregations, simple
     predicates). Anything it cannot account for - `system`, `value`, a second
     statement, a function it doesn't know, brackets, assignment - makes it
     REJECT, fail-closed.
  2. RECOMPILE that structured request through the trusted QueryCompiler, which
     re-validates table/column/op allowlists and emits bounded, date-filtered,
     entitlement-injected q.

The crucial property: **the agent's raw q is never executed.** We run only the
compiler's output, derived from the lifted request. So a lifter bug can only ever
(a) reject, or (b) produce a request the compiler then re-validates and bounds -
never run dangerous text. The lifter is a recogniser, not the security boundary;
the compiler is the boundary, a second time.

Honest scope: the recognised grammar is a curated subset that grows. Computed
arithmetic columns, sort/limit wrappers, and exotic forms are not lifted yet -
they are REJECTED (safe), and the caller falls back to the structured tool or
break-glass. This is deliberately conservative: reject-by-default.

Stdlib-only. No q process, no Node, no kqagent.
"""

from __future__ import annotations

import re

from .query_compiler import QueryCompiler

# Aggregations we recognise in a select item (mirror the compiler's set).
_AGG = {"avg", "sum", "min", "max", "count", "first", "last", "dev", "var", "med"}
_DYADIC = {"wavg", "wsum"}
_SCALAR_OPS = {"=", "<", ">", "<=", ">="}

_DATE = re.compile(r"^\d{4}\.\d{2}\.\d{2}$")

# Tokenizer. Anything that falls to `other` (e.g. {, [, ], :, %, +, -, *, !, \,
# @, .) is a token we don't allow in the safe subset -> the parse rejects.
# Recent-window "now" support. `.z.p - 0D00:05` is matched as ONE token so the
# bare '-' and '.' never enter the token stream (they stay rejected everywhere
# else). Only pure current-time/date reads are recognised; the compiler
# re-validates and emits the function itself. `nowrel` must precede `now`.
_NOWFN = r"\.z\.[pPdDtTnzZ]"
_SPAN = r"\d+D\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?|\d{2}:\d{2}(?::\d{2})?"
_TOK = re.compile(r"""
    (?P<ws>\s+)
  | (?P<nowrel>\.z\.[pPdDtTnzZ]\s*-\s*(?:\d+D\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?|\d{2}:\d{2}(?::\d{2})?))
  | (?P<now>\.z\.[pPdDtTnzZ])
  | (?P<date>\d{4}\.\d{2}\.\d{2})
  | (?P<float>\d+\.\d+)
  | (?P<int>\d+)
  | (?P<sym>`[A-Za-z0-9_.]*)
  | (?P<str>"(?:[^"\\]|\\.)*")
  | (?P<op><=|>=|[=<>])
  | (?P<punct>[(),;])
  | (?P<word>[A-Za-z][A-Za-z0-9_]*)
  | (?P<other>.)
""", re.VERBOSE)

_ALLOWED_OTHER = {":"}  # ':' is allowed only as an alias separator (checked in context)


class FreeformRejected(Exception):
    """The free-form q is not in the safe subset and was not lifted."""


class _Tok:
    __slots__ = ("kind", "val")

    def __init__(self, kind, val):
        self.kind, self.val = kind, val

    def __repr__(self):
        return f"{self.kind}:{self.val}"


def _tokenize(s: str) -> list[_Tok]:
    toks = []
    for m in _TOK.finditer(s):
        kind = m.lastgroup
        val = m.group()
        if kind == "ws":
            continue
        if kind == "other" and val not in _ALLOWED_OTHER:
            raise FreeformRejected(f"unexpected token {val!r} - not in the safe q subset")
        toks.append(_Tok(kind, val))
    if not toks:
        raise FreeformRejected("empty query")
    return toks


def _split_top(toks: list[_Tok], sep: str = ",") -> list[list[_Tok]]:
    """Split a token list on a top-level separator (depth 0 w.r.t. parens)."""
    out, cur, depth = [], [], 0
    for t in toks:
        if t.kind == "punct" and t.val == "(":
            depth += 1
        elif t.kind == "punct" and t.val == ")":
            depth -= 1
            if depth < 0:
                raise FreeformRejected("unbalanced parentheses")
        if depth == 0 and t.kind == "punct" and t.val == sep:
            out.append(cur); cur = []
        else:
            cur.append(t)
    if depth != 0:
        raise FreeformRejected("unbalanced parentheses")
    out.append(cur)
    return out


def _value(toks: list[_Tok]):
    """Lift a scalar value token sequence to a Python value the compiler accepts."""
    if len(toks) == 1:
        t = toks[0]
        if t.kind == "nowrel":            # `.z.p - 0D00:05` -> structured relative value
            m = re.match(rf"({_NOWFN})\s*-\s*({_SPAN})$", t.val)
            if not m:
                raise FreeformRejected(f"malformed relative time: {t.val!r}")
            return {"now_minus": m.group(2), "fn": m.group(1)}
        if t.kind == "now":               # bare `.z.p`
            return {"now": True, "fn": t.val}
        if t.kind == "date":
            return t.val
        if t.kind == "int":
            return int(t.val)
        if t.kind == "float":
            return float(t.val)
        if t.kind == "sym":
            return t.val[1:]              # strip leading backtick
        if t.kind == "str":
            return t.val[1:-1]            # strip quotes (used for like patterns)
        raise FreeformRejected(f"unsupported value {t.val!r}")
    # back-to-back symbols: `AAPL`MSFT  -> ['AAPL','MSFT']
    if toks and all(t.kind == "sym" for t in toks):
        return [t.val[1:] for t in toks]
    raise FreeformRejected("unsupported compound value")


def _sym_list(toks: list[_Tok]) -> list:
    """Lift the RHS of `in`: `AAPL`MSFT  or  (`AAPL;`MSFT)  or  (1;2)."""
    if toks and toks[0].kind == "punct" and toks[0].val == "(":
        if toks[-1].val != ")":
            raise FreeformRejected("malformed list")
        inner = toks[1:-1]
        return [_value(p) for p in _split_top(inner, ";")]
    # bare back-to-back symbols
    if toks and all(t.kind == "sym" for t in toks):
        return [t.val[1:] for t in toks]
    raise FreeformRejected("'in' needs a symbol list or (a;b) list")


def _parse_select_item(toks: list[_Tok], req: dict) -> None:
    """One comma-separated select item -> add to columns / aggs / select."""
    alias = None
    # alias:  word ':' body   (':' shows up as an 'other' token)
    if len(toks) >= 2 and toks[0].kind == "word" and toks[1].kind == "other" and toks[1].val == ":":
        alias = toks[0].val
        toks = toks[2:]
    if not toks:
        raise FreeformRejected("empty select item")

    words = [t.val for t in toks]

    # plain column: a single identifier
    if len(toks) == 1 and toks[0].kind == "word":
        if alias:
            req.setdefault("select", []).append({"as": alias, "expr": {"col": words[0]}})
        else:
            req.setdefault("columns", []).append(words[0])
        return
    # count i  /  count distinct col
    if words[0] == "count" and len(words) == 2 and words[1] == "i":
        req.setdefault("aggs", []).append({"fn": "count", **({"as": alias} if alias else {})})
        return
    if words[0] == "count" and len(words) == 3 and words[1] == "distinct" and toks[2].kind == "word":
        req.setdefault("aggs", []).append({"fn": "countdistinct", "col": words[2], **({"as": alias} if alias else {})})
        return
    # agg over a null-predicate: `fn null col` (e.g. `sum null bid` counts nulls).
    # `null` is the only allowed modifier; the compiler re-validates it.
    if len(toks) == 3 and words[0] in _AGG and words[1] == "null" and toks[2].kind == "word":
        req.setdefault("aggs", []).append({"fn": words[0], "col": words[2], "of": "null",
                                           **({"as": alias} if alias else {})})
        return
    # monadic agg: fn col
    if len(toks) == 2 and words[0] in _AGG and toks[1].kind == "word":
        req.setdefault("aggs", []).append({"fn": words[0], "col": words[1], **({"as": alias} if alias else {})})
        return
    # dyadic agg: weight wavg col  (e.g. size wavg price)
    if len(toks) == 3 and words[1] in _DYADIC and toks[0].kind == "word" and toks[2].kind == "word":
        req.setdefault("aggs", []).append({"fn": words[1], "weight": words[0], "col": words[2],
                                           **({"as": alias} if alias else {})})
        return
    raise FreeformRejected(f"select item not in the safe subset: {' '.join(words)}")


def _parse_where_pred(toks: list[_Tok], req: dict) -> None:
    """One comma-separated where predicate -> date or a structured filter."""
    if not toks or toks[0].kind != "word":
        raise FreeformRejected("predicate must start with a column")
    col = toks[0].val
    rest = toks[1:]

    # date predicates -> the request's date object
    if col == "date":
        if rest and rest[0].kind == "op" and rest[0].val == "=" and len(rest) == 2 and rest[1].kind == "date":
            req["date"] = {"from": rest[1].val, "to": rest[1].val}
            return
        if rest and rest[0].kind == "word" and rest[0].val == "within" and len(rest) == 3 \
                and rest[1].kind == "date" and rest[2].kind == "date":
            req["date"] = {"from": rest[1].val, "to": rest[2].val}
            return
        raise FreeformRejected("unsupported date predicate")

    filt = {"col": col}
    if rest and rest[0].kind == "op" and rest[0].val in _SCALAR_OPS:
        filt["op"] = rest[0].val
        filt["value"] = _value(rest[1:])
    elif rest and rest[0].kind == "word" and rest[0].val == "in":
        filt["op"] = "in"
        filt["value"] = _sym_list(rest[1:])
    elif rest and rest[0].kind == "word" and rest[0].val == "within":
        body = rest[1:]
        if body and body[0].kind == "punct" and body[0].val == "(":
            parts = _split_top(body[1:-1], ";")
            if len(parts) != 2:
                raise FreeformRejected("'within' needs (lo;hi)")
            filt["op"] = "within"; filt["value"] = [_value(parts[0]), _value(parts[1])]
        elif len(body) == 2:
            filt["op"] = "within"; filt["value"] = [_value([body[0]]), _value([body[1]])]
        else:
            raise FreeformRejected("unsupported 'within' predicate")
    elif rest and rest[0].kind == "word" and rest[0].val == "like" and len(rest) == 2 and rest[1].kind == "str":
        filt["op"] = "like"; filt["value"] = rest[1].val[1:-1]
    else:
        raise FreeformRejected(f"unsupported predicate on '{col}'")
    req.setdefault("filters", []).append(filt)


def lift(qtext: str) -> dict:
    """Lift a free-form q string into a structured request, or raise
    FreeformRejected. Recognises: [select|exec] <list> [by <list>] from <table>
    [where <preds>]  and  meta <table>. Everything else is rejected."""
    if qtext.count('"') % 2:
        raise FreeformRejected("unbalanced string quote")
    toks = _tokenize(qtext)

    # exactly one statement: reject a TOP-LEVEL ';' (depth 0). A ';' inside parens
    # is the list separator in (`a;`b) and is fine.
    _depth = 0
    for t in toks:
        if t.kind == "punct" and t.val == "(":
            _depth += 1
        elif t.kind == "punct" and t.val == ")":
            _depth -= 1
        elif _depth == 0 and t.kind == "punct" and t.val == ";":
            raise FreeformRejected("multiple statements are not allowed")

    head = toks[0]
    if head.kind != "word" or head.val not in ("select", "exec", "meta"):
        raise FreeformRejected("only select / meta are allowed")
    # `exec` returns a flat list, not a table; the compiler only emits `select`, so
    # lifting exec->select would silently change the RESULT SHAPE. Reject rather than
    # run a non-equivalent query (we only ever run a semantically-equivalent safe q).
    if head.val == "exec":
        raise FreeformRejected("exec (flat-list result) is not in the safe subset yet - use select")

    if head.val == "meta":
        if len(toks) == 2 and toks[1].kind == "word":
            return {"table": toks[1].val, "op": "meta"}
        raise FreeformRejected("meta takes a single table")

    req: dict = {}
    i = 1
    if toks[i].kind == "word" and toks[i].val == "distinct":
        req["distinct"] = True
        i += 1

    # find the top-level 'by' and 'from' keywords
    def find_kw(name, lo):
        depth = 0
        for j in range(lo, len(toks)):
            t = toks[j]
            if t.kind == "punct" and t.val == "(":
                depth += 1
            elif t.kind == "punct" and t.val == ")":
                depth -= 1
            elif depth == 0 and t.kind == "word" and t.val == name:
                return j
        return -1

    j_from = find_kw("from", i)
    if j_from < 0:
        raise FreeformRejected("missing 'from'")
    j_by = find_kw("by", i)
    sel_end = j_by if 0 <= j_by < j_from else j_from

    sel_toks = toks[i:sel_end]
    if sel_toks:                       # empty select-list = select all columns
        for item in _split_top(sel_toks):
            _parse_select_item(item, req)

    if 0 <= j_by < j_from:
        for item in _split_top(toks[j_by + 1:j_from]):
            if len(item) == 1 and item[0].kind == "word":
                req.setdefault("by", []).append(item[0].val)
            else:
                raise FreeformRejected("'by' supports plain columns only")

    # table: single word after 'from', up to optional 'where'
    j_where = find_kw("where", j_from + 1)
    tbl_toks = toks[j_from + 1: (j_where if j_where >= 0 else len(toks))]
    if len(tbl_toks) != 1 or tbl_toks[0].kind != "word":
        raise FreeformRejected("'from' must name a single table")
    req["table"] = tbl_toks[0].val

    if j_where >= 0:
        for pred in _split_top(toks[j_where + 1:]):
            if pred:
                _parse_where_pred(pred, req)

    return req


def compile_freeform(qtext: str, compiler: QueryCompiler, principal: str | None = None) -> str:
    """Lift free-form q to a structured request and recompile it through the
    trusted compiler. Raises FreeformRejected (not liftable) or
    StructuredQueryRejected (lifted but fails the compiler's allowlists). The
    agent's raw q is never executed - only the returned compiler output is."""
    req = lift(qtext)
    return compiler.compile(req, principal=principal)


# --- secondary advisory layer (foot-gun messages; NOT the control) -----------

_FOOTGUNS = [
    ("non-date-first-scan", re.compile(r"(?is)\bfrom\s+\w+\s+where\s+(?!date\b)"),
     "first where predicate is not the date/partition column - risks a full-partition scan (OOM)"),
    ("string-equals", re.compile(r"=\s*\""), "`=` against a string literal - throws 'length or is silently wrong"),
    ("no-where", re.compile(r"(?is)\bfrom\s+\w+\s*$"), "no where clause - unbounded scan"),
]


def advisories(qtext: str) -> list[str]:
    """Best-effort foot-gun notes for context/logging. Advisory only - the real
    control is lift()+recompile, which rejects anything not in the safe subset."""
    return [msg for _, rx, msg in _FOOTGUNS if rx.search(qtext)]
