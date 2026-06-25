"""Propose policy widenings from the audit log of blocked-but-maybe-legit attempts.

The shadow/audit log records every BLOCK and REQUIRE_APPROVAL the gate produced.
This tool turns that log into a review queue: it groups the blocked decisions by
(tool, rule, reason-shape), ranks them by frequency, and surfaces the top shapes as
WIDENING CANDIDATES for a human to consider. For a candidate that maps to a concrete
grant (e.g. "grant tool X"), it builds the proposed policy and runs it through
`monotonic_confinement.guard_policy_update`, so the operator sees whether the change
is a narrowing (confinement-preserving, auto-applyable) or a widening (allow-set
grows -> needs sign-off).

It NEVER edits or signs a policy. It only proposes. Pairs with monitor mode
(AEGIS_MODE=monitor): run the policy in shadow, collect the would-be blocks here,
review the candidates, then tighten/loosen the policy deliberately.

    python -m aegis.widen_from_log --audit chat-audit.jsonl [--min-count 2] [--policy policy.json]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

_BLOCKED = {"block", "require_approval"}


def read_blocked(path: str | Path) -> list[dict]:
    """Read an audit JSONL; return the BLOCK / REQUIRE_APPROVAL entries."""
    out = []
    p = Path(path)
    if not p.exists():
        return out
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if str(e.get("effect", "")).lower() in _BLOCKED:
            out.append(e)
    return out


def group(entries: list[dict]) -> list[dict]:
    """Group blocked entries by (tool, first-rule, reason-prefix); count + sample."""
    buckets: dict[tuple, dict] = {}
    counts: dict[tuple, int] = defaultdict(int)
    for e in entries:
        tool = e.get("tool", "?")
        rules = e.get("rules") or []
        reasons = e.get("reasons") or []
        rule = rules[0] if rules else "(none)"
        reason = (reasons[0] if reasons else "").strip()
        key = (tool, rule, reason[:70])
        counts[key] += 1
        b = buckets.setdefault(key, {"tool": tool, "rule": rule, "reason": reason,
                                     "effect": e.get("effect"), "samples": []})
        if len(b["samples"]) < 3 and e.get("target"):
            b["samples"].append(e["target"])
    rows = [{**buckets[k], "count": counts[k]} for k in buckets]
    rows.sort(key=lambda r: r["count"], reverse=True)
    return rows


def _grant_candidate(tool: str, policy: dict) -> dict | None:
    """If `tool` is not granted by the policy, propose adding it. Adding a grant
    enlarges the allow-set, so it is by definition a WIDENING (operator sign-off
    required). Returns None if the policy shape is unknown or the tool is already
    granted. monotonic_confinement.guard_policy_update is what ENFORCES this on the
    signed load path; here we only surface the candidate + its classification."""
    grants = (policy or {}).get("grants", {})
    granted = grants.get("tools")
    if granted is None:
        return None
    has = (tool in granted) if isinstance(granted, (list, set, dict)) else False
    if has:
        return None
    return {"change": f"grant tool '{tool}'", "verdict": "widening",
            "note": "adds to the allow-set — monotonic_confinement flags this on the "
                    "signed load path and routes it for approval"}


def analyze(entries: list[dict], policy: dict | None = None, min_count: int = 1) -> list[dict]:
    """Return ranked widening candidates (>= min_count), each with an optional
    policy-diff classification."""
    out = []
    for row in group(entries):
        if row["count"] < min_count:
            continue
        cand = dict(row)
        if policy is not None:
            diff = _grant_candidate(row["tool"], policy)
            if diff is not None:
                cand["proposed"] = diff
        out.append(cand)
    return out


def _render(cands: list[dict]) -> str:
    if not cands:
        return "No blocked/approval decisions found — nothing to widen."
    lines = [f"{len(cands)} blocked shape(s), most frequent first "
             "(review before changing policy — widenings need sign-off):", ""]
    for c in cands:
        lines.append(f"  [{c['count']:>4}x] {c['effect']:<16} tool={c['tool']}  rule={c['rule']}")
        if c.get("reason"):
            lines.append(f"         reason: {c['reason']}")
        if c.get("proposed"):
            p = c["proposed"]
            lines.append(f"         -> candidate: {p['change']}  ==> classification: {p['verdict'].upper()}"
                         + (f" (+{len(p['newly_allowed'])} newly allowed)" if p.get("newly_allowed") else ""))
        lines.append("")
    lines.append("This tool only PROPOSES. Apply widenings deliberately, then re-sign the policy.")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Propose policy widenings from blocked-attempt audit log")
    ap.add_argument("--audit", required=True, help="path to the audit JSONL")
    ap.add_argument("--policy", help="optional policy.json to classify grant candidates against")
    ap.add_argument("--min-count", type=int, default=1, help="only show shapes blocked >= N times")
    a = ap.parse_args(argv)
    entries = read_blocked(a.audit)
    policy = json.loads(Path(a.policy).read_text(encoding="utf-8")) if a.policy else None
    print(_render(analyze(entries, policy, a.min_count)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
