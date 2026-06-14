"""Runtime supervisor — second line of defence with an automated kill switch.

The per-action engine decides ONE action at a time. The supervisor watches the
SEQUENCE of decisions and trips a circuit breaker when the agent's *behaviour*
(not any single call) looks like an incident: probing the guardrails, trying to
touch protected assets, escalating, or emitting actions that match no known
classification ("no correct action code"). When a tripwire fires it:

  1. trips a per-principal CIRCUIT BREAKER — the engine then BLOCKS every
     further action from that principal (fail-closed; the agent cannot ignore
     it, the decision lives in the PDP);
  2. fires a configurable KILL strategy (SIGTERM the agent pid / `docker kill`
     / `kubectl delete pod` / a callback) to actually stop the LLM;
  3. writes an INCIDENT record — deterministic facts + a timeline — that an
     optional LLM overseer (aegis.overseer) can narrate.

Design, consistent with the rest of Aegis:
  * DETERMINISTIC and stdlib-only — this is load-bearing, so it never depends
    on an LLM being available or correct. (The LLM overseer is separate and
    advisory.)
  * FAIL-CLOSED — a breaker store that cannot be read trips closed; a tripped
    breaker survives PDP restart (persisted).
  * MONITOR-AWARE — in monitor mode the supervisor still OBSERVES and writes
    incidents, but does not actually block or hard-kill unless
    `enforce_in_monitor` is set. This lets you tune tripwires on real traffic
    before arming the kill switch (the monitor-then-enforce discipline).

policy.json:
    "supervisor": {
        "enabled": true,
        "breaker_store": ".aegis/breakers.json",
        "incident_dir": ".aegis/incidents",
        "window_seconds": 300,
        "enforce_in_monitor": false,
        "kill": {"strategy": "none"},          # none|signal|command|callback
        "tripwires": {
            "repeated_blocks":   {"max_blocks": 3},
            "escalation_rate":   {"max_per_minute": 10},
            "critical_rules":    {"rule_ids": ["PRD-PROTECTED-PATH","PII-EGRESS",
                                               "SEC-PRIVATE-KEY-BLOCK","DENY-PATH-NOT-WRITABLE"]},
            "approval_abuse":    {"max_approvals": 8},
            "unknown_action":    {"enabled": true}
        }
    }
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

# Tools the system understands. An action whose tool is none of these and whose
# decision carried no rule at all is "unclassified" — the unknown_action
# tripwire treats that as suspicious ("no correct action code").
_KNOWN_TOOLS = {
    "Bash", "Shell", "PowerShell", "Read", "Write", "Edit", "MultiEdit",
    "NotebookEdit", "Glob", "Grep", "run_query", "run_structured_query", "read_file",
}


def _now() -> float:
    return time.time()


@dataclass
class Incident:
    incident_id: str
    principal: str
    tripwire: str
    reason: str
    triggered_ts: float
    window_seconds: float
    timeline: list[dict] = field(default_factory=list)   # recent {ts,tool,effect,rules,target}
    killed: bool = False
    kill_detail: str = ""
    narrative: str = ""        # optional, filled by the LLM overseer

    def render(self) -> str:
        lines = [
            f"AEGIS INCIDENT {self.incident_id}",
            f"  principal:  {self.principal}",
            f"  tripwire:   {self.tripwire}",
            f"  reason:     {self.reason}",
            f"  at:         {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(self.triggered_ts))}",
            f"  kill:       {'EXECUTED — ' + self.kill_detail if self.killed else 'not executed (monitor/none)'}",
            f"  window:     last {int(self.window_seconds)}s, {len(self.timeline)} events",
            "  timeline (most recent last):",
        ]
        for e in self.timeline[-12:]:
            ts = time.strftime("%H:%M:%S", time.gmtime(e.get("ts", 0)))
            rules = ",".join(e.get("rules", [])) or "-"
            lines.append(f"    {ts}  {e.get('effect','?'):<16} {e.get('tool',''):<10} "
                         f"{str(e.get('target',''))[:48]:<48} [{rules}]")
        if self.narrative:
            lines += ["", "  overseer narrative:", "    " + self.narrative.replace("\n", "\n    ")]
        return "\n".join(lines)


class CircuitBreaker:
    """Per-principal armed/tripped state, persisted and fail-closed."""

    def __init__(self, store_path: str | Path):
        self.path = Path(store_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _read(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8") or "{}")
        except (json.JSONDecodeError, OSError):
            # Unreadable breaker store: fail closed — treat as "everything
            # tripped" so a corrupted safety mechanism cannot silently allow.
            return {"__corrupt__": True}

    def is_tripped(self, principal: str) -> bool:
        d = self._read()
        if d.get("__corrupt__"):
            return True
        rec = d.get(principal)
        return bool(rec and rec.get("tripped"))

    def trip(self, principal: str, incident_id: str, reason: str) -> None:
        d = self._read()
        if d.get("__corrupt__"):
            d = {}
        d[principal] = {"tripped": True, "incident_id": incident_id,
                        "reason": reason, "ts": _now()}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(d, indent=1, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.path)

    def reset(self, principal: str) -> bool:
        """Operator action — clear a breaker after handling the incident."""
        d = self._read()
        if d.get("__corrupt__"):
            d = {}
        if principal in d:
            del d[principal]
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(d, indent=1, sort_keys=True), encoding="utf-8")
            os.replace(tmp, self.path)
            return True
        return False


class _KillSwitch:
    """Pluggable hard-kill. `none` relies on the breaker (soft kill: the PDP
    blocks everything). The others actually terminate the agent."""

    def __init__(self, cfg: dict | None, callback=None):
        self.cfg = cfg or {"strategy": "none"}
        self.callback = callback

    def fire(self, principal: str, incident_id: str, context: dict) -> tuple[bool, str]:
        strat = self.cfg.get("strategy", "none")
        try:
            if strat == "none":
                return False, "soft kill only (breaker blocks all further actions)"
            if strat == "callback" and self.callback:
                self.callback(principal, incident_id, context)
                return True, "callback invoked"
            if strat == "signal":
                pid = context.get("pid") or self.cfg.get("pid")
                if not pid:
                    return False, "signal strategy but no pid available"
                sig = getattr(signal, self.cfg.get("signal", "SIGTERM"), signal.SIGTERM)
                os.kill(int(pid), sig)
                return True, f"sent {self.cfg.get('signal','SIGTERM')} to pid {pid}"
            if strat == "command":
                # Template like ["docker","kill","{container}"] or
                # ["kubectl","delete","pod","{pod}"]; {placeholders} from context+cfg.
                tmpl = self.cfg.get("command", [])
                args = [a.format(**{**self.cfg, **context}) for a in tmpl]
                if not args:
                    return False, "command strategy but no command configured"
                r = subprocess.run(args, capture_output=True, text=True, timeout=15)
                return (r.returncode == 0), f"ran {' '.join(args)} (rc={r.returncode})"
        except Exception as e:  # a kill that errors must not crash the gate
            return False, f"kill strategy '{strat}' errored: {type(e).__name__}: {e}"
        return False, f"unknown kill strategy '{strat}'"


class Supervisor:
    """Watches the decision stream, trips the breaker + kills on a tripwire."""

    def __init__(self, cfg: dict, kill_callback=None):
        self.cfg = cfg or {}
        self.window = float(self.cfg.get("window_seconds", 300))
        self.enforce_in_monitor = bool(self.cfg.get("enforce_in_monitor", False))
        self.breaker = CircuitBreaker(self.cfg.get("breaker_store", ".aegis/breakers.json"))
        self.incident_dir = Path(self.cfg.get("incident_dir", ".aegis/incidents"))
        self.incident_dir.mkdir(parents=True, exist_ok=True)
        self.kill = _KillSwitch(self.cfg.get("kill"), kill_callback)
        self.tw = self.cfg.get("tripwires", {})
        # In-memory per-principal event window. (For a multi-process PDP this
        # would be a shared store; loopback single-process is the common case.)
        self._events: dict[str, list[dict]] = {}
        self._seq = 0

    # -- the breaker check the engine consults -----------------------------

    def is_tripped(self, principal: str) -> bool:
        return self.breaker.is_tripped(principal or "unknown")

    # -- observe each decision ---------------------------------------------

    def observe(self, action, decision, *, mode: str = "enforce",
                context: dict | None = None) -> Incident | None:
        """Feed one (action, decision). Returns an Incident if a tripwire fired
        on THIS observation, else None. Always records to the event window."""
        principal = action.principal or "unknown"
        rules = [f.rule_id for f in decision.findings]
        effect = (decision.shadow_effect or decision.effect)
        effect_val = getattr(effect, "value", str(effect))
        ev = {
            "ts": _now(), "tool": action.tool, "effect": effect_val,
            "rules": rules,
            "target": action.file_path or (action.command or "")[:120],
        }
        win = self._events.setdefault(principal, [])
        win.append(ev)
        cutoff = _now() - self.window
        win[:] = [e for e in win if e["ts"] >= cutoff]

        tripped = self._evaluate_tripwires(principal, ev, win)
        if not tripped:
            return None
        tripwire, reason = tripped

        # already tripped? don't re-incident on every subsequent call
        if self.breaker.is_tripped(principal):
            return None

        self._seq += 1
        incident_id = f"INC-{int(ev['ts'])}-{self._seq:03d}"
        incident = Incident(
            incident_id=incident_id, principal=principal, tripwire=tripwire,
            reason=reason, triggered_ts=ev["ts"], window_seconds=self.window,
            timeline=list(win),
        )

        active = (mode != "monitor") or self.enforce_in_monitor
        if active:
            self.breaker.trip(principal, incident_id, reason)
            killed, detail = self.kill.fire(principal, incident_id, context or {})
            incident.killed = killed
            incident.kill_detail = detail
        else:
            incident.kill_detail = "monitor mode: incident recorded, kill NOT executed"

        self._write_incident(incident)
        return incident

    # -- tripwires (deterministic) -----------------------------------------

    def _evaluate_tripwires(self, principal: str, ev: dict, win: list[dict]):
        tw = self.tw

        crit = set((tw.get("critical_rules") or {}).get("rule_ids", []))
        if crit and crit.intersection(ev["rules"]):
            hit = sorted(crit.intersection(ev["rules"]))
            return "critical_rules", f"critical rule(s) fired: {', '.join(hit)}"

        ua = tw.get("unknown_action")
        # A deployment can declare its own tool surface via known_tools, extending
        # the built-in defaults — so a new analyst tool isn't mistaken for a probe.
        known = _KNOWN_TOOLS | set((ua or {}).get("known_tools", []))
        if ua and ua.get("enabled") and ev["tool"] not in known and not ev["rules"]:
            return "unknown_action", (f"unclassified action '{ev['tool']}' with no policy "
                                      f"classification (no recognised action code)")

        rb = tw.get("repeated_blocks")
        if rb:
            n = sum(1 for e in win if e["effect"] == "block")
            if n >= int(rb.get("max_blocks", 3)):
                return "repeated_blocks", f"{n} blocked actions within {int(self.window)}s (probing)"

        ab = tw.get("approval_abuse")
        if ab:
            n = sum(1 for e in win if e["effect"] == "require_approval")
            if n >= int(ab.get("max_approvals", 8)):
                return "approval_abuse", f"{n} approval-required actions within {int(self.window)}s"

        er = tw.get("escalation_rate")
        if er:
            recent = [e for e in win if e["ts"] >= _now() - 60]
            blocks = sum(1 for e in recent if e["effect"] in ("block", "require_approval"))
            if blocks >= int(er.get("max_per_minute", 10)):
                return "escalation_rate", f"{blocks} blocked/approval actions in the last 60s"

        return None

    def _write_incident(self, incident: Incident) -> None:
        base = self.incident_dir / incident.incident_id
        base.with_suffix(".json").write_text(
            json.dumps(asdict(incident), indent=1), encoding="utf-8")
        base.with_suffix(".txt").write_text(incident.render(), encoding="utf-8")


# ---------------------------------------------------------------------------
# Operator CLI — list incidents, show one, reset a tripped breaker.
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    import argparse
    from pathlib import Path as _P

    ap = argparse.ArgumentParser(description="Aegis runtime supervisor — operator CLI")
    ap.add_argument("cmd", choices=["status", "incidents", "show", "reset"],
                    help="status: list tripped breakers; incidents: list incidents; "
                         "show <id>: print one incident; reset <principal>: clear a breaker")
    ap.add_argument("arg", nargs="?", default=None)
    ap.add_argument("--breaker-store", default=".aegis/breakers.json")
    ap.add_argument("--incident-dir", default=".aegis/incidents")
    a = ap.parse_args(argv)

    if a.cmd == "status":
        b = CircuitBreaker(a.breaker_store)
        d = b._read()
        if d.get("__corrupt__"):
            print("breaker store CORRUPT — failing closed (all principals blocked)")
            return 1
        tripped = {k: v for k, v in d.items() if v.get("tripped")}
        if not tripped:
            print("no tripped breakers")
        for p, rec in tripped.items():
            print(f"TRIPPED  {p}  incident={rec.get('incident_id')}  reason={rec.get('reason')}")
        return 0

    if a.cmd == "incidents":
        idir = _P(a.incident_dir)
        files = sorted(idir.glob("*.txt")) if idir.exists() else []
        if not files:
            print("(no incidents)")
        for f in files:
            print(f.stem)
        return 0

    if a.cmd == "show":
        if not a.arg:
            print("usage: show <incident_id>"); return 2
        f = _P(a.incident_dir) / f"{a.arg}.txt"
        if not f.exists():
            print(f"no such incident: {a.arg}"); return 1
        print(f.read_text(encoding="utf-8"))
        return 0

    if a.cmd == "reset":
        if not a.arg:
            print("usage: reset <principal>"); return 2
        ok = CircuitBreaker(a.breaker_store).reset(a.arg)
        print(f"breaker for '{a.arg}': {'reset' if ok else 'was not tripped'}")
        return 0
    return 2


if __name__ == "__main__":
    import sys
    sys.exit(main())
