"""Test: widen_from_log groups blocked attempts + classifies grant candidates."""
from __future__ import annotations

from . import widen_from_log as W


def _mk(tool, effect, rule, reason, target=""):
    return {"tool": tool, "effect": effect, "rules": [rule], "reasons": [reason], "target": target}


def run() -> bool:
    entries = [
        _mk("export_tool", "block", "GRANTS-DENY", "tool not granted", "export_tool"),
        _mk("export_tool", "block", "GRANTS-DENY", "tool not granted", "export_tool"),
        _mk("export_tool", "block", "GRANTS-DENY", "tool not granted", "export_tool"),
        _mk("query_fsp_data", "block", "aegis.block.lifter", "unexpected token '.'", "tables[]"),
        _mk("restart_process", "require_approval", "PROD-PROTECT", "needs sign-off", "restart gateway"),
    ]
    # non-blocked rows must be ignored
    raw = entries + [_mk("query_fsp_data", "allow", "aegis.rewrite.tool", "")]

    g = W.group([e for e in raw if e["effect"] in W._BLOCKED])
    assert g[0]["tool"] == "export_tool" and g[0]["count"] == 3, f"top group wrong: {g[0]}"
    assert any(r["effect"] == "require_approval" for r in g), "approval row missing"
    assert all(r["count"] >= 1 for r in g)

    policy = {"grants": {"tools": ["query_fsp_data", "restart_process"]}}  # export_tool NOT granted
    cands = W.analyze([e for e in raw if e["effect"] in W._BLOCKED], policy, min_count=2)
    # export_tool (3x) should appear with a WIDENING classification; query (1x) filtered by min_count=2
    top = cands[0]
    assert top["tool"] == "export_tool", f"expected export_tool top, got {top['tool']}"
    assert "proposed" in top, "expected a grant candidate for the ungranted tool"
    assert top["proposed"]["verdict"] == "widening", f"granting a new tool must be a WIDENING: {top['proposed']}"
    assert "note" in top["proposed"]
    assert not any(c["tool"] == "query_fsp_data" for c in cands), "min_count=2 should filter the 1x query block"

    # at min_count=1 the granted tools appear but get NO grant candidate (already allowed)
    all_cands = W.analyze([e for e in raw if e["effect"] in W._BLOCKED], policy, min_count=1)
    rp = [c for c in all_cands if c["tool"] == "restart_process"]
    assert rp and "proposed" not in rp[0], "already-granted tool should have no grant candidate"
    qf = [c for c in all_cands if c["tool"] == "query_fsp_data"]
    assert qf and "proposed" not in qf[0], "already-granted tool should have no grant candidate"

    # render must not crash and must mention the widening
    out = W._render(cands)
    assert "WIDENING" in out and "export_tool" in out
    print("widen_from_log_test: PASS (grouping, min-count, widening classification, no-op on granted)")
    return True


if __name__ == "__main__":
    import sys
    sys.exit(0 if run() else 1)
