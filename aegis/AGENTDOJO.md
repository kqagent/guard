# Benchmarking Aegis against AgentDojo

[AgentDojo](https://arxiv.org/abs/2406.13352) (Debenedetti et al., NeurIPS 2024;
adopted by UK AISI `inspect_evals`) is the field's standard dynamic benchmark
for agent robustness to prompt injection delivered through tool outputs — 97
tasks, 629 security cases, across workspace / banking / travel / Slack suites.
Progent and PCAS both report defenses against it; for credible competitive
positioning, Aegis should too.

## Two distinct measurements (don't conflate them)

| | What it measures | Needs a live model? | In this repo |
|---|---|---|---|
| **Official AgentDojo** | end-to-end *utility under attack*: does the agent still do the task, and does the injection succeed? | **Yes** (every task = model calls) | run externally (below) |
| **Aegis model-independent** | does the gate BLOCK the attacker's tool call at execution even if the model is fully compromised, while ALLOWING benign task calls? | **No** (deterministic) | `agentdojo_eval.py` |

The model-independent view is the honest one for a *deterministic gate*: Aegis
doesn't try to stop the model from being fooled — it stops the fooled model's
action from executing. That's measurable without spending a cent.

`python -m aegis.agentdojo_eval` → **defense 1.00 / utility 1.00** on a corpus
mirroring AgentDojo's attack effect-classes (exfiltration, unauthorized
transfer, account takeover, destruction) and benign workspace/banking tools.
The benign `send_email` is *allowed* while the exfiltrating `send_email` is
blocked — the gate discriminates on arguments, it doesn't blanket-block.

> This is **AgentDojo-aligned**, not the official 629-case score. It validates
> the integration and the named-tool defense; it is not a substitute for the
> end-to-end run.

## Running the real suite (when you have model budget)

The harness is built: `tools/run_agentdojo_official.py` wires an
`AegisGatedExecutor` (a drop-in for AgentDojo's `ToolsExecutor` that checks
every model-requested call against an Aegis `tool_rules` policy) into the
official pipeline, with per-suite starter policies for
workspace/banking/travel/slack.

```bash
pip install agentdojo                                  # already in the [benchmarks] extra

python tools/run_agentdojo_official.py --dry-run       # no key: verifies wiring
                                                       # (passes: 97 tasks across 4 suites load,
                                                       #  attack-shaped calls block, benign allow)

export ANTHROPIC_API_KEY=...
python tools/run_agentdojo_official.py --suites banking --tasks 3   # cost-sized smoke
python tools/run_agentdojo_official.py                              # the full official run
```

It reports benign utility / utility under attack / targeted attack success
per suite (summary.json), and writes a per-call decision log
(decisions-<suite>.json) for tuning the `block_if` argument predicates.

Report the three AgentDojo metrics with Aegis on vs off:
- **benign utility** (no attack),
- **utility under attack** (task success despite injection),
- **targeted attack success rate** — this is the number Aegis should drive
  toward 0 (Progent reports 0%).

## Building a real named-tool policy

`agentdojo_eval.py` uses the `tool_rules` pack (per-tool effect + optional
`block_if` regex over arguments). For a full AgentDojo policy, enumerate each
suite's tools and gate the state-changing ones (send_email/send_money/
post_webpage/delete/forwarding/password) with argument predicates; leave
read-only tools ungated. In production, layer default-deny grants underneath so
any tool without an explicit rule is denied, not allowed.

## Honest gaps

- `tool_rules.block_if` is a regex over concatenated args — adequate for the
  effect-classes here, but a real deployment wants typed argument predicates
  (recipient-domain allowlists, amount thresholds) — the Progent/PCAS direction.
- The official score requires the live-model run; until that's funded, cite the
  model-independent defense rate and say so plainly.
