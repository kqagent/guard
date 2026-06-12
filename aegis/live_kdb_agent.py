"""Live shadow-pilot: an Anthropic agent with kdb+ tools, every call gated.

This is the end-to-end pilot demo the rollout plan calls for: a real LLM
agent given kdb-shaped tools (run_query, read_file), with EVERY tool call
brokered through Aegis before it executes. Default mode is MONITOR (shadow):
nothing is blocked, but the would-be decision is recorded — so you can
measure the false-positive rate on real agent traffic before flipping to
enforce. That is exactly the "monitor, measure FP, then enforce" discipline.

Two real enforcement surfaces are wired:
  * the AegisSession gate (engine in monitor or enforce mode) on every tool call
  * the QueryGuard query proxy on run_query — it parses/bounds/rewrites the q
    the model emits, so the q process only ever receives a safe query
The query results come from a real local q process (the kdb moat in action).

    python -m aegis.live_kdb_agent --dry-run
        No key, no q: drives the gate + query proxy with canned model
        tool-calls (a benign bounded query and an unbounded-scan attempt)
        and prints the shadow decisions. Proves the wiring offline.

    set ANTHROPIC_API_KEY=...   (and a valid kc.lic so q runs)
    python -m aegis.live_kdb_agent --task "How many AAPL trades today?"
        Live: the model plans tool calls; Aegis gates each; q runs the safe
        query; decisions logged to .aegis/shadow-decisions.jsonl.

    python -m aegis.live_kdb_agent --task "..." --enforce
        Same, but BLOCK is real and the model gets the refusal fed back.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from shutil import which

from .engine import Engine
from .guard import Guard
from .model import Action, Effect
from .query_proxy import QueryGuard, QueryRejected

_SEED = (
    "n:1000;trade:([] date:n?(2026.06.11; 2026.06.12); "
    "sym:n?`AAPL`MSFT`GOOG; px:n?100f; sz:n?1000);"
)

KDB_TOOLS = [
    {"name": "run_query",
     "description": "Run a read-only q/kdb+ query against the trade database and return rows.",
     "input_schema": {"type": "object",
                      "properties": {"query": {"type": "string"}},
                      "required": ["query"]}},
    {"name": "read_file",
     "description": "Read a file from the analyst scratch area.",
     "input_schema": {"type": "object",
                      "properties": {"path": {"type": "string"}},
                      "required": ["path"]}},
]


def _find_q() -> str | None:
    if os.environ.get("Q_BIN"):
        return os.environ["Q_BIN"]
    qhome = os.environ.get("QHOME")
    if qhome:
        for rel in ("w64/q.exe", "l64/q", "m64/q"):
            if (Path(qhome) / rel).exists():
                return str(Path(qhome) / rel)
    return which("q")


class KdbTools:
    """Executors. run_query enforces the query proxy before touching q."""

    def __init__(self, query_guard: QueryGuard, q_bin: str | None):
        self.query_guard = query_guard
        self.q_bin = q_bin

    def run_query(self, query: str) -> str:
        try:
            safe = self.query_guard.enforce(query)   # rewrite/allow or raise
        except QueryRejected as e:
            return f"QUERY REJECTED BY PROXY: {e}"
        if not self.q_bin:
            return f"(no q available) proxy-approved query: {safe}"
        script = f"{_SEED}\nres:{safe.replace('.z.d', '2026.06.12')};\n-1 .Q.s res;\nexit 0;"
        try:
            p = subprocess.run([self.q_bin, "-q"], input=script,
                               capture_output=True, text=True, timeout=20)
        except Exception as e:
            return f"q execution error: {type(e).__name__}"
        out = (p.stdout or "") + (p.stderr or "")
        if "license error" in out:
            return "q licence invalid/expired — cannot execute"
        return out.strip()[:2000]

    def read_file(self, path: str) -> str:
        return f"(stub) contents of {path}"


# --------------------------------------------------------------------------

def _gate_decision(guard: Guard, tool: str, args: dict, principal: str):
    return guard.engine.evaluate(Action(tool=tool, tool_input=args, principal=principal))


def dry_run() -> int:
    print("=== live kdb agent — dry run (gate + query proxy wiring) ===\n")
    guard = Guard(Engine.load(Path(__file__).with_name("policy.kdb.json")))
    # monitor mode: shadow the verdict, don't block
    guard.engine.mode = "monitor"
    tools = KdbTools(QueryGuard.from_policy(Path(__file__).with_name("policy.kdb.json")), _find_q())

    canned = [
        ("run_query", {"query": "select from trade"},
         "unbounded scan — proxy should bound it"),
        ("run_query", {"query": "select[100] from trade where date=2026.06.12"},
         "already bounded — should pass clean"),
        ("read_file", {"path": "/scratch/notes.txt"}, "benign read"),
        ("run_query", {"query": "delete from trade"},
         "mutation — proxy must reject; gate destructive_ops shadow-flags"),
    ]
    for tool, args, note in canned:
        d = _gate_decision(guard, tool, args, principal="analyst-agent")
        shadow = (d.shadow_effect or d.effect).value
        print(f"- {tool}({json.dumps(args)})  [{note}]")
        print(f"    gate shadow-decision: {shadow}"
              + (f"  rules={[f.rule_id for f in d.findings]}" if d.findings else ""))
        if tool == "run_query":
            v = tools.query_guard.analyze(args["query"])
            print(f"    query proxy: {v.action}"
                  + (f" -> {v.safe_query}" if v.action == "rewrite" else "")
                  + (f"  ({v.reasons[0]})" if v.reasons else ""))
            print(f"    executor result: {tools.run_query(args['query'])[:120]}")
        print()
    print("PASS — gate + query proxy wired; monitor mode shadows decisions "
          "without blocking. Set ANTHROPIC_API_KEY + a valid kc.lic for a live run.")
    return 0


def live_run(task: str, model: str, enforce: bool, max_turns: int) -> int:
    import anthropic

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ANTHROPIC_API_KEY not set — run with --dry-run to prove wiring.")
        return 2

    guard = Guard.load(Path(__file__).with_name("policy.kdb.json"),
                       audit_path=".aegis/shadow-audit.jsonl")
    guard.engine.mode = "enforce" if enforce else "monitor"
    tools = KdbTools(QueryGuard.from_policy(Path(__file__).with_name("policy.kdb.json")), _find_q())
    client = anthropic.Anthropic()
    log_path = Path(".aegis/shadow-decisions.jsonl")
    log_path.parent.mkdir(parents=True, exist_ok=True)

    messages = [{"role": "user", "content": task}]
    print(f"=== live kdb agent ({'ENFORCE' if enforce else 'MONITOR'}, {model}) ===")
    print(f"task: {task}\n")

    for turn in range(max_turns):
        resp = client.messages.create(model=model, max_tokens=1024,
                                      tools=KDB_TOOLS, messages=messages)
        messages.append({"role": "assistant", "content": resp.content})
        tool_uses = [b for b in resp.content if getattr(b, "type", None) == "tool_use"]
        for b in resp.content:
            if getattr(b, "type", None) == "text" and b.text.strip():
                print(f"[model] {b.text.strip()[:300]}")
        if not tool_uses:
            break

        results = []
        for tu in tool_uses:
            d = _gate_decision(guard, tu.name, tu.input, principal="analyst-agent")
            shadow = (d.shadow_effect or d.effect).value
            with log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"turn": turn, "tool": tu.name, "args": tu.input,
                                    "enforced": d.effect.value, "would_be": shadow,
                                    "rules": [f.rule_id for f in d.findings]}) + "\n")
            print(f"[gate] {tu.name} -> enforced={d.effect.value} would_be={shadow}"
                  + (f" rules={[f.rule_id for f in d.findings]}" if d.findings else ""))
            if d.effect is Effect.BLOCK:
                content = Guard.refusal_text(d)
            else:
                fn = getattr(tools, tu.name, None)
                content = fn(**tu.input) if fn else f"unknown tool {tu.name}"
            results.append({"type": "tool_result", "tool_use_id": tu.id, "content": str(content)})
        messages.append({"role": "user", "content": results})

    print(f"\ndecisions logged to {log_path}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--task", default=None)
    ap.add_argument("--model", default="claude-haiku-4-5-20251001")
    ap.add_argument("--enforce", action="store_true",
                    help="block for real (default is monitor/shadow mode)")
    ap.add_argument("--max-turns", type=int, default=6)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if args.dry_run or not args.task:
        return dry_run()
    return live_run(args.task, args.model, args.enforce, args.max_turns)


if __name__ == "__main__":
    sys.exit(main())
