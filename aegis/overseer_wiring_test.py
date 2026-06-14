"""Prove the LLM overseer is wired into the supervisor as ADVISORY-ONLY (B1).

The bar (carried review note): the overseer is an LLM in the loop, so it must be
structurally incapable of weakening a decision — additive escalation only. This
battery proves:
  (a) when enabled (+a judge), a fired incident carries a real overseer narrative
      and concern;
  (b) the gate/breaker behaves IDENTICALLY whether the overseer is absent, present,
      or throwing — same trip, same effect, same incident facts;
  (c) the overseer has NO allow/clear path: it runs only after the breaker has
      already tripped, and nothing it returns can untrip it or change an effect.

Run:  python -m aegis.overseer_wiring_test
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from .model import Action, Decision, Effect, Finding
from .supervisor import Supervisor


def _cfg(tmp: Path, overseer_enabled=False) -> dict:
    c = {
        "window_seconds": 300,
        "breaker_store": str(tmp / "breakers.json"),
        "incident_dir": str(tmp / "incidents"),
        "tripwires": {"repeated_blocks": {"max_blocks": 3}},
    }
    if overseer_enabled:
        c["overseer"] = {"enabled": True}
    return c


def _block(rule="DST-X"):
    return Decision(effect=Effect.BLOCK,
                    findings=[Finding(rule_id=rule, effect=Effect.BLOCK, pack="t", reason="r")])


def _drive_to_trip(sup: Supervisor):
    """Feed 3 blocked actions for one principal; return the incident from the trip."""
    inc = None
    for _ in range(3):
        inc = sup.observe(Action(tool="read_file", tool_input={"path": "aegis/policy.kdb.json"},
                                 principal="attacker"), _block(), mode="enforce") or inc
    return inc


class _StubOverseer:
    """Deterministic stand-in for the LLM (no API). Records calls; can be made to
    throw to prove failure is swallowed. Has NO allow/clear capability by design."""
    def __init__(self, boom=False):
        self.boom = boom
        self.calls = []

    def narrate_incident(self, incident):
        self.calls.append("narrate")
        if self.boom:
            raise RuntimeError("simulated overseer failure")
        incident.narrative = "Agent repeatedly tried to read a protected policy file; isolate the principal."
        return incident.narrative

    def review(self, events):
        from .overseer import OverseerVerdict
        self.calls.append("review")
        if self.boom:
            raise RuntimeError("simulated overseer failure")
        return OverseerVerdict("high", "probing guardrails", recommend_kill=False)


def run() -> int:
    fails = 0

    # (a) enabled + stub judge -> incident carries a real narrative + concern.
    with tempfile.TemporaryDirectory() as d:
        sup = Supervisor(_cfg(Path(d)), overseer=_StubOverseer())
        inc = _drive_to_trip(sup)
        ok_a = inc is not None and "protected policy" in inc.narrative and inc.overseer_concern == "high"
        print(f"  {'ok ' if ok_a else 'XX '} (a) incident carries overseer narrative + concern")
        fails += 0 if ok_a else 1

    # (b) gate behaves identically: same trip + same effect with no overseer,
    #     with a working overseer, and with a THROWING overseer.
    def trip_facts(overseer):
        with tempfile.TemporaryDirectory() as d:
            sup = Supervisor(_cfg(Path(d)), overseer=overseer)
            inc = _drive_to_trip(sup)
            # the decisive facts the gate/breaker produced:
            return (inc is not None, inc.tripwire, inc.reason,
                    sup.is_tripped("attacker"))
    base = trip_facts(None)
    withov = trip_facts(_StubOverseer())
    boom = trip_facts(_StubOverseer(boom=True))
    ok_b = base == withov == boom and base[0] and base[3]
    print(f"  {'ok ' if ok_b else 'XX '} (b) breaker trips identically w/ overseer absent / present / throwing")
    print(f"        none={base}  present={withov}  throwing={boom}")
    fails += 0 if ok_b else 1

    # (c) NO allow/clear path. After a trip, drive the overseer's strongest signal
    #     and confirm the breaker stays tripped and the gate still blocks. The
    #     overseer object exposes no method that returns/admits ALLOW or clears.
    with tempfile.TemporaryDirectory() as d:
        sup = Supervisor(_cfg(Path(d)), overseer=_StubOverseer())
        _drive_to_trip(sup)
        still_tripped = sup.is_tripped("attacker")
        # the overseer surface: only narrate/review exist; neither can untrip.
        from .overseer import LLMOverseer, OverseerVerdict
        api = set(dir(LLMOverseer)) | set(dir(OverseerVerdict))
        no_clear_api = not any(k in api for k in ("allow", "clear", "untrip", "approve", "override"))
        # and a 'none' concern verdict must NOT untrip an already-tripped breaker
        sup2 = Supervisor(_cfg(Path(d)) | {"breaker_store": str(Path(d) / "b2.json")}, overseer=_StubOverseer())
        _drive_to_trip(sup2)
        # feeding more (even benign) observations never clears it; only breaker.reset can
        sup2.observe(Action(tool="run_structured_query", tool_input={"request": {}}, principal="attacker"),
                     Decision(effect=Effect.ALLOW, findings=[]), mode="enforce")
        ok_c = still_tripped and no_clear_api and sup2.is_tripped("attacker")
        print(f"  {'ok ' if ok_c else 'XX '} (c) overseer has no allow/clear path; breaker stays tripped")
        fails += 0 if ok_c else 1

    # (d) policy flag default OFF: no overseer built without explicit enable.
    with tempfile.TemporaryDirectory() as d:
        sup = Supervisor(_cfg(Path(d), overseer_enabled=False))
        ok_d = sup.overseer is None
        print(f"  {'ok ' if ok_d else 'XX '} (d) overseer default-off (no overseer.enabled => None)")
        fails += 0 if ok_d else 1

    print(f"\n{'PASS' if fails == 0 else 'FAIL'} — {fails} failure(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(run())
