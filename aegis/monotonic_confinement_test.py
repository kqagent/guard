"""Prove the monotonic-confinement policy-diff guard: a policy update may only
SHRINK the allow-set without approval; a widening is flagged with the exact
newly-allowed actions; identity is a no-op; fail-closed if a policy won't load.

Run:  python -m aegis.monotonic_confinement_test
"""

from __future__ import annotations

import copy
import sys

from .monotonic_confinement import (classify_policy_change, guard_policy_update,
                                     WideningRequiresApproval)

# A small but realistic kdb analyst policy.
BASE = {
    "fail_mode": "closed",
    "enabled_packs": ["secrets", "destructive_ops"],
    "grants": {"tools": ["run_structured_query", "read_file"]},
    "secrets": {"effect": "block"},
    "destructive": {"effect": "block"},
}


def run() -> int:
    fails = 0

    def check(name, cond, detail=""):
        nonlocal fails
        print(f"  {'ok ' if cond else 'XX '} {name}")
        if not cond:
            fails += 1
            if detail:
                print(f"        {detail}")

    # 1. identity -> no change.
    r = classify_policy_change(BASE, copy.deepcopy(BASE))
    check("1 identical policy -> identity", r["verdict"] == "identity", r)

    # 2. narrowing: remove a granted tool -> allow-set shrinks -> auto-apply.
    narrowed = copy.deepcopy(BASE)
    narrowed["grants"]["tools"] = ["run_structured_query"]   # dropped read_file
    r = classify_policy_change(BASE, narrowed)
    check("2 dropping a granted tool -> narrowing", r["verdict"] == "narrowing", r)
    check("2b narrowing auto-applies (guard returns, no raise)",
          guard_policy_update(BASE, narrowed)["verdict"] == "narrowing")

    # 3. WIDENING: grant a new, more-powerful tool -> require approval + name it.
    widened = copy.deepcopy(BASE)
    widened["grants"]["tools"] = ["run_structured_query", "read_file", "run_query", "submit_order"]
    r = classify_policy_change(BASE, widened)
    check("3 granting run_query/submit_order -> widening", r["verdict"] == "widening", r)
    check("3b widening names the specific newly-allowed actions",
          any("run_query" in x or "submit_order" in x for x in r["newly_allowed"]), r["newly_allowed"])

    # 4. widening is BLOCKED without approval, ALLOWED with approval.
    blocked = False
    try:
        guard_policy_update(BASE, widened)
    except WideningRequiresApproval:
        blocked = True
    check("4 widening without approval -> raises WideningRequiresApproval", blocked)
    try:
        ok_approved = guard_policy_update(BASE, widened, approved=True)["verdict"] == "widening"
    except WideningRequiresApproval:
        ok_approved = False
    check("4b widening WITH explicit approval -> allowed", ok_approved)

    # 5. relaxing a pack effect (block -> allow on destructive) is a widening —
    #    but ONLY where it actually adds an allowed action. With grants gating the
    #    tool, the allow-set is unchanged (correctly identity); to exercise the pack
    #    relaxation we grant Bash so `rm -rf /data` is gated by the pack, not grants.
    bash_base = copy.deepcopy(BASE)
    bash_base["grants"]["tools"] = ["run_structured_query", "read_file", "Bash"]
    bash_relaxed = copy.deepcopy(bash_base)
    bash_relaxed["destructive"] = {"effect": "allow"}   # block -> allow on rm/etc.
    r = classify_policy_change(bash_base, bash_relaxed)
    check("5 relaxing destructive block->allow (Bash granted) -> widening", r["verdict"] == "widening", r)
    check("5b widening names a newly-allowed destructive command",
          any("rm" in x.lower() for x in r["newly_allowed"]), r["newly_allowed"])

    # 6. fail-closed: a policy that won't load.
    r = classify_policy_change(BASE, {"not": "a policy"})
    check("6 unloadable new policy -> fail_closed", r["verdict"] == "fail_closed", r)
    fc_raised = False
    try:
        guard_policy_update(BASE, {"bad": 1})
    except WideningRequiresApproval:
        fc_raised = True
    check("6b fail_closed denies auto-apply (raises)", fc_raised)

    print(f"\n{'PASS' if fails == 0 else 'FAIL'} — {fails} failure(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(run())
