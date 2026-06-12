"""SMT (Z3) proofs of the grant algebra — over UNBOUNDED domains.

`aegis.formal` proves default-deny soundness and monotonic confinement by
exhaustion over a bounded, representative action universe: a real
implementation-vs-spec check, but only over the actions it enumerates.
This module discharges the same properties with Z3 over the UNBOUNDED
domain — every possible string, not 50 modeled actions — which is the
Progent / PCAS standard of evidence.

What is proved (and what is not):

  T1  UNBOUNDED DEFAULT-DENY COMPLETENESS (concrete policy):
      For ALL strings tool, binary, path: if the action uses ANY component
      outside the policy.json grant lists, the grant algebra DENIES it.
      Z3 searches the infinite string space for a counterexample (some
      ungranted string that is still allowed); UNSAT = proof.

  T2  PATH-NARROWING LEMMA (concrete policy, unbounded paths):
      For every single-prefix removal from grants.writable_paths and ALL
      path strings x:  under_any(narrowed, x) => under_any(full, x).
      I.e. dropping a writable prefix can only shrink the writable set.

  T3  MEMBERSHIP-NARROWING LEMMA (concrete policy, unbounded strings):
      Same for tools and binaries: dropping a granted element can only
      shrink the allowed set, for every possible string.

  T4  MONOTONIC CONFINEMENT (ARBITRARY policies, unbounded actions):
      For arbitrary grant predicates G and G' with G' pointwise narrower
      (forall x: G'(x) => G(x), per capability class), and an arbitrary
      symbolic action:  allow_{G'}(a) => allow_G(a).
      This quantifies over the POLICY too — every narrowing of every
      policy, not just single-element removals from ours.

Honesty note: these theorems are about the grant ALGEBRA as modeled here.
Conformance of `engine._check_grants` (the running Python) to this algebra
is what `aegis.formal` checks exhaustively against the independent spec.
Together: SMT proves the algebra unboundedly; exhaustion ties the
implementation to it. Detector-pattern evasion is out of scope for both —
that is `redteam_corpus`'s job, and THREAT_MODEL.md is candid about it.

Run:  python -m aegis.formal_smt          (needs `pip install z3-solver`,
                                           the `formal` extra; exits 3 if absent)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

POLICY = Path(__file__).with_name("policy.json")


def _norm_prefix(p: str) -> str:
    return p.replace("\\", "/").rstrip("/").lstrip("./")


def run() -> int:
    try:
        import z3
    except ImportError:
        print("skip: z3-solver not installed (pip install 'aegis-guardrails[formal]')")
        return 3

    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    grants = policy.get("grants", {})
    tools = list(grants.get("tools", []))
    bins = list(grants.get("binaries", []))
    prefixes = [_norm_prefix(p) for p in grants.get("writable_paths", [])]

    S = z3.StringSort()

    def member(x, items):
        """x is one of the concrete granted strings."""
        return z3.Or([x == z3.StringVal(i) for i in items]) if items else z3.BoolVal(False)

    def under_any(x, prefs):
        """The engine's path rule: x == prefix or x startswith prefix + '/'."""
        cases = []
        for p in prefs:
            pv = z3.StringVal(p)
            pslash = z3.StringVal(p + "/")
            cases.append(z3.Or(x == pv, z3.PrefixOf(pslash, x)))
        return z3.Or(cases) if cases else z3.BoolVal(False)

    def prove(name: str, claim) -> bool:
        """Prove validity of `claim` by refuting its negation."""
        s = z3.Solver()
        s.set("timeout", 60_000)
        s.add(z3.Not(claim))
        r = s.check()
        if r == z3.unsat:
            print(f"  {name}: PROVED (unsat — no counterexample exists)")
            return True
        if r == z3.sat:
            print(f"  {name}: VIOLATED — counterexample: {s.model()}")
        else:
            print(f"  {name}: UNDECIDED ({r}) — treat as failure")
        return False

    print("=== Aegis formal properties (Z3, unbounded domains) ===\n")
    print(f"  policy grants: {len(tools)} tools, {len(bins)} binaries, "
          f"{len(prefixes)} writable prefixes\n")
    ok = True

    # -- T1: unbounded default-deny completeness (concrete policy) ----------
    # The grant algebra over fully symbolic action components. An action
    # uses: a tool, optionally a command binary, optionally a written path.
    # The claim is the contrapositive form of default-deny: an action using
    # ANY ungranted component is denied — for every string in the infinite
    # domain, not just the bounded universe `aegis.formal` enumerates.
    tool = z3.String("tool")
    binary = z3.String("binary")
    path = z3.String("path")
    uses_cmd = z3.Bool("uses_cmd")
    writes = z3.Bool("writes")

    engine_allow = z3.And(
        member(tool, tools),
        z3.Implies(uses_cmd, member(binary, bins)),
        z3.Implies(writes, under_any(path, prefixes)),
    )
    uses_ungranted = z3.Or(
        z3.Not(member(tool, tools)),
        z3.And(uses_cmd, z3.Not(member(binary, bins))),
        z3.And(writes, z3.Not(under_any(path, prefixes))),
    )
    ok &= prove("T1 default-deny completeness (ungranted component => denied, all strings)",
                z3.Implies(uses_ungranted, z3.Not(engine_allow)))

    # -- T2: path-narrowing lemma (concrete, unbounded paths) ---------------
    x = z3.String("x")
    for i, dropped in enumerate(prefixes):
        narrowed = [p for j, p in enumerate(prefixes) if j != i]
        ok &= prove(f"T2 path narrowing  (-'{dropped}' shrinks writable set)",
                    z3.ForAll([x], z3.Implies(under_any(x, narrowed),
                                              under_any(x, prefixes))))

    # -- T3: membership-narrowing lemma (concrete, unbounded strings) -------
    for label, items in (("tool", tools), ("binary", bins)):
        for i, dropped in enumerate(items):
            narrowed = [v for j, v in enumerate(items) if j != i]
            ok &= prove(f"T3 {label} narrowing  (-'{dropped}' shrinks allowed set)",
                        z3.ForAll([x], z3.Implies(member(x, narrowed),
                                                  member(x, items))))

    # -- T4: monotonic confinement for ARBITRARY policies --------------------
    # Grant predicates are uninterpreted functions — they stand for ANY
    # policy. The only assumption is pointwise narrowing. The action is fully
    # symbolic. So this is: every narrowing of every policy can only shrink
    # the allow-set, over the unbounded action space.
    toolG = z3.Function("toolG", S, z3.BoolSort())
    toolG2 = z3.Function("toolG2", S, z3.BoolSort())
    binG = z3.Function("binG", S, z3.BoolSort())
    binG2 = z3.Function("binG2", S, z3.BoolSort())
    pathG = z3.Function("pathG", S, z3.BoolSort())
    pathG2 = z3.Function("pathG2", S, z3.BoolSort())

    v = z3.String("v")
    narrower = z3.And(
        z3.ForAll([v], z3.Implies(toolG2(v), toolG(v))),
        z3.ForAll([v], z3.Implies(binG2(v), binG(v))),
        z3.ForAll([v], z3.Implies(pathG2(v), pathG(v))),
    )

    def abstract_allow(tg, bg, pg):
        return z3.And(
            tg(tool),
            z3.Implies(uses_cmd, bg(binary)),
            z3.Implies(writes, pg(path)),
        )

    ok &= prove("T4 monotonic confinement  (arbitrary narrower policy => allow-set shrinks)",
                z3.Implies(
                    z3.And(narrower, abstract_allow(toolG2, binG2, pathG2)),
                    abstract_allow(toolG, binG, pathG),
                ))

    n = 1 + len(prefixes) + len(tools) + len(bins) + 1
    print(f"\n{'PASS' if ok else 'FAIL'} — {n} theorems over unbounded string domains "
          f"(T4 additionally over arbitrary policies)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(run())
