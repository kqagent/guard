"""Proving battery for the runtime supervisor + circuit breaker + kill switch.

  1. critical-rule tripwire: one action firing a critical rule trips the
     breaker immediately; the NEXT action from that principal is BLOCKED by
     SUPERVISOR-TRIPPED even though it is itself benign (session quarantined).
  2. the kill callback fires on trip, with the incident id.
  3. an incident file (json + txt) is written with a timeline.
  4. repeated-blocks tripwire: N blocked actions in the window trips it.
  5. unknown_action tripwire: an unclassified tool with no rule trips it.
  6. monitor mode: incident is recorded but the breaker does NOT block and the
     kill is NOT fired (shadow) — unless enforce_in_monitor.
  7. operator reset clears the breaker; the principal can act again.
  8. fail-closed: a corrupt breaker store quarantines everyone.

Run:  python -m aegis.supervisor_test
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from .engine import Engine
from .model import Action, Effect
from .supervisor import CircuitBreaker, Supervisor

_checks: list[tuple[str, bool]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    _checks.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))


def _sup_cfg(tmp: Path, **over) -> dict:
    cfg = {
        "enabled": True,
        "breaker_store": str(tmp / "breakers.json"),
        "incident_dir": str(tmp / "incidents"),
        "window_seconds": 300,
        "kill": {"strategy": "none"},
        "tripwires": {
            "critical_rules": {"rule_ids": ["PRD-PROTECTED-PATH", "PII-EGRESS"]},
            "repeated_blocks": {"max_blocks": 3},
            "unknown_action": {"enabled": True},
        },
    }
    cfg.update(over)
    return cfg


def _policy() -> dict:
    return {
        "enabled_packs": ["destructive_ops", "prod_protection"],
        "destructive": {"effect": "block"},
        "prod": {"effect": "block", "patterns": []},
        "protected_paths": ["aegis/policy.json"],
    }


def _act(tool, **inp):
    return Action(tool=tool, tool_input=inp, principal="rogue-agent")


def run() -> int:
    print("=== runtime supervisor + kill switch ===\n")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_sup_"))

    # 1+2+3. critical rule trips immediately, kill callback fires, incident written
    killed = {}
    def killer(principal, incident_id, ctx):
        killed["principal"] = principal
        killed["incident"] = incident_id
    sup = Supervisor(_sup_cfg(tmp), kill_callback=killer)
    sup.kill.cfg = {"strategy": "callback"}     # arm the callback strategy
    eng = Engine(_policy(), audit=None, supervisor=sup)

    # action that touches a protected path -> PRD-PROTECTED-PATH (critical)
    d = eng.evaluate(_act("Edit", file_path="aegis/policy.json", new_string="x"))
    check("triggering action is blocked by the gate", d.effect is Effect.BLOCK)
    check("breaker tripped on critical rule", sup.is_tripped("rogue-agent"))
    check("kill callback fired with incident id",
          killed.get("principal") == "rogue-agent" and killed.get("incident", "").startswith("INC-"))

    # next action is benign but the session is quarantined
    d2 = eng.evaluate(_act("Read", path="scratch/ok.txt"))
    check("subsequent benign action BLOCKED by SUPERVISOR-TRIPPED",
          d2.effect is Effect.BLOCK and any(f.rule_id == "SUPERVISOR-TRIPPED" for f in d2.findings))

    inc_files = list((tmp / "incidents").glob("*.txt"))
    check("incident file written (txt + json)",
          len(inc_files) == 1 and inc_files[0].with_suffix(".json").exists())
    if inc_files:
        body = inc_files[0].read_text(encoding="utf-8")
        check("incident has timeline + reason", "timeline" in body and "critical rule" in body)

    # 7. operator reset clears it
    ok = CircuitBreaker(str(tmp / "breakers.json")).reset("rogue-agent")
    check("operator reset clears the breaker", ok and not sup.is_tripped("rogue-agent"))
    d3 = eng.evaluate(_act("Read", path="scratch/ok.txt"))
    check("after reset, benign action allowed again", d3.effect is Effect.ALLOW)

    # 4. repeated-blocks tripwire (no critical rule; just many blocks)
    tmp2 = Path(tempfile.mkdtemp(prefix="aegis_sup2_"))
    sup2 = Supervisor(_sup_cfg(tmp2))
    eng2 = Engine(_policy(), audit=None, supervisor=sup2)
    for _ in range(3):
        eng2.evaluate(_act("Bash", command="rm -rf /data"))   # destructive -> block
    check("repeated-blocks tripwire trips after N blocks", sup2.is_tripped("rogue-agent"))

    # 5. unknown_action tripwire (unclassified tool, no rule fires)
    tmp3 = Path(tempfile.mkdtemp(prefix="aegis_sup3_"))
    sup3 = Supervisor(_sup_cfg(tmp3))
    eng3 = Engine({"enabled_packs": []}, audit=None, supervisor=sup3)
    eng3.evaluate(Action(tool="WeirdUndeclaredTool", tool_input={}, principal="rogue-agent"))
    check("unknown_action tripwire trips on unclassified tool", sup3.is_tripped("rogue-agent"))

    # 6. monitor mode: incident recorded, breaker does NOT block, kill NOT fired
    tmp4 = Path(tempfile.mkdtemp(prefix="aegis_sup4_"))
    killed4 = {}
    sup4 = Supervisor(_sup_cfg(tmp4), kill_callback=lambda *a: killed4.setdefault("fired", True))
    sup4.kill.cfg = {"strategy": "callback"}
    eng4 = Engine(_policy(), audit=None, supervisor=sup4, mode="monitor")
    eng4.evaluate(_act("Edit", file_path="aegis/policy.json", new_string="x"))
    inc4 = list((tmp4 / "incidents").glob("*.txt"))
    check("monitor mode records the incident", len(inc4) == 1)
    check("monitor mode does NOT trip the breaker (shadow)", not sup4.is_tripped("rogue-agent"))
    check("monitor mode does NOT fire the kill", "fired" not in killed4)
    d5 = eng4.evaluate(_act("Read", path="scratch/ok.txt"))
    check("monitor mode: next action still allowed", d5.effect is Effect.ALLOW)

    # 8. fail-closed: corrupt breaker store quarantines everyone
    corrupt = tmp / "breakers.json"
    corrupt.write_text("{not json", encoding="utf-8")
    check("corrupt breaker store => fail-closed (tripped)",
          Supervisor(_sup_cfg(tmp)).is_tripped("anybody"))

    failed = [n for n, ok in _checks if not ok]
    print(f"\n{'PASS' if not failed else 'FAIL'} — {len(_checks) - len(failed)}/{len(_checks)} checks")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(run())
