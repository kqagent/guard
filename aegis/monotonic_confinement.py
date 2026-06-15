"""Monotonic-confinement guard for POLICY UPDATES (Progent-style).

A policy change may only ever SHRINK the agent's allow-set without explicit
approval. Given (old_policy, new_policy) we classify the diff by comparing the
allow-sets each induces over the modeled action universe (the same exhaustion the
`formal.py` P2 proof uses, lifted from single-element narrowings of ONE policy to
a diff over TWO arbitrary policies):

  * identity   — same allow-set            -> auto-apply (no change)
  * narrowing  — allow(new) ⊆ allow(old)    -> auto-apply (confinement preserved)
  * widening   — allow(new) ⊄ allow(old)    -> REQUIRE APPROVAL; report exactly the
                 newly-allowed actions
  * fail_closed — either policy won't load  -> deny auto-apply (treat as widening)

Wire `guard_policy_update` into the policy load/sign path so an unreviewed widening
cannot ship. (Unbounded-domain corroboration: the Z3 path in `formal_smt` proves
monotonic confinement symbolically; this exhaustive diff is the stdlib backstop.)
"""

from __future__ import annotations

import sys

from .engine import Engine
from .model import Action, Effect
from .formal import action_universe, _key


def _kdb_actions() -> list[Action]:
    """Extend the generic universe with the kdb analyst tool surface, so a
    narrowing/widening of a kdb policy's grants is actually visible in the diff."""
    return [
        Action(tool="run_structured_query", tool_input={"request": {"table": "trade"}}),
        Action(tool="run_query", tool_input={"query": "select from trade where date=2025.06.01"}),
        Action(tool="read_file", tool_input={"path": "scratch/notes.txt"}),
        Action(tool="submit_order", tool_input={"sym": "AAPL", "side": "buy", "qty": 1}),
        Action(tool="send_email", tool_input={"to": "x@y", "body": "b"}),
    ]


def default_universe() -> list[Action]:
    return action_universe() + _kdb_actions()


def _loadable(policy) -> bool:
    return isinstance(policy, dict) and ("enabled_packs" in policy or "grants" in policy)


def allow_set(policy: dict, universe: list[Action]) -> set:
    """The set of universe actions this policy ALLOWS (enforce mode). The diff is a
    function of the STATIC authorization surface (grants + detector effects), so the
    runtime supervisor/circuit-breaker is disabled — otherwise transient breaker
    state would make every policy look identical (all-blocked)."""
    import copy
    p = copy.deepcopy(policy)
    p.setdefault("supervisor", {})["enabled"] = False
    eng = Engine(p, audit=None)
    eng.mode = "enforce"
    out = set()
    for a in universe:
        try:
            if eng.evaluate(a).effect is Effect.ALLOW:
                out.add(_key(a))
        except Exception:
            pass   # an action the engine can't evaluate is not "allowed"
    return out


def classify_policy_change(old: dict, new: dict, universe: list[Action] | None = None) -> dict:
    """Classify new vs old. Returns {verdict, newly_allowed, removed}."""
    if not _loadable(old) or not _loadable(new):
        return {"verdict": "fail_closed", "newly_allowed": [], "removed": [],
                "reason": "a policy could not be loaded (missing enabled_packs/grants) — denying auto-apply"}
    u = universe or default_universe()
    a_old, a_new = allow_set(old, u), allow_set(new, u)
    newly = sorted(a_new - a_old)   # actions the NEW policy allows that the old did not
    removed = sorted(a_old - a_new)
    if newly:
        verdict = "widening"
    elif removed:
        verdict = "narrowing"
    else:
        verdict = "identity"
    return {"verdict": verdict, "newly_allowed": newly, "removed": removed}


class WideningRequiresApproval(Exception):
    """A policy update widens the allow-set and was not explicitly approved."""


def guard_policy_update(old: dict, new: dict, *, approved: bool = False,
                        universe: list[Action] | None = None) -> dict:
    """Gate a policy update on the load/sign path. Auto-applies identity/narrowing;
    raises on widening (unless `approved`) and on fail_closed. Returns the
    classification dict on success."""
    result = classify_policy_change(old, new, universe)
    if result["verdict"] == "fail_closed":
        raise WideningRequiresApproval(result.get("reason", "policy failed to load — fail-closed"))
    if result["verdict"] == "widening" and not approved:
        raise WideningRequiresApproval(
            "policy update WIDENS the allow-set (newly-allowed: "
            + ", ".join(result["newly_allowed"]) + ") — explicit approval required before it can ship")
    return result


# -- standalone demo / CLI ----------------------------------------------------

def main() -> int:
    import json
    if len(sys.argv) >= 3:
        old = json.loads(open(sys.argv[1]).read())
        new = json.loads(open(sys.argv[2]).read())
        r = classify_policy_change(old, new)
        print(json.dumps(r, indent=1))
        return 0 if r["verdict"] in ("identity", "narrowing") else 1
    print("usage: python -m aegis.monotonic_confinement <old_policy.json> <new_policy.json>")
    return 2


if __name__ == "__main__":
    sys.exit(main())
