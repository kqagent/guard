# Go-ahead: full official AgentDojo run, all 4 suites, Opus, with vs without IFC

Approved spend. You sized the wiring at n=1/Haiku (works; benign_utility 0.0 was
Haiku/n=1 noise, not IFC). This is the real number.

## Run

All four suites, Opus, the important_instructions attack, and crucially BOTH
configs so the delta isolates IFC's contribution:

```bash
# with IFC (the full stack)
python tools/run_agentdojo_official.py --suites workspace banking travel slack \
    --model claude-opus-4-8 --logdir runs/agentdojo/ifc-on
# without IFC (gate = detectors only, IFC disabled) — the baseline
AEGIS_DISABLE_IFC=1 python tools/run_agentdojo_official.py --suites workspace banking travel slack \
    --model claude-opus-4-8 --logdir runs/agentdojo/ifc-off
```

(Use whatever flag/env you wired for the IFC toggle; the point is two runs that
differ ONLY in IFC, on the same model + suites + attack.)

Cost control: it's your call whether to run the full per-suite task set (the
literal 97-task / 629-case official number) or cap at `--tasks 10` per suite
first to confirm Opus produces meaningful utility, then go full. Confirm-before-
spend on the magnitude as you see fit — you own the key and the budget.

## Report back

Per suite AND aggregated, for BOTH configs:
- `benign_utility` (tasks still succeed, no attack)
- `utility_under_attack` (task success despite injection)
- `targeted_attack_success` (the headline — drive to 0)

The two numbers that matter:
1. **targeted_attack_success with vs without IFC** — does IFC drive it toward 0,
   and by how much over the detector-only baseline? This is the head-to-head vs
   FIDES/Progent (both report ~0%).
2. **utility_under_attack with IFC** — IFC must NOT tank benign utility
   (over-tainting would show here). Sanity-check any utility-0 against the
   without-IFC baseline + the task trace, exactly as you did at n=1 — don't
   attribute model/task noise to the gate.

Attach `summary.json` and the per-suite decision logs. If the Opus utility comes
out healthy and attack-success lands at/near 0 with IFC, that's the recognized
external number that closes the "we have a bespoke corpus, not AgentDojo numbers"
gap — fold it into the assurance story and `AGENTDOJO.md`.

Honest-scope reminder: report the real numbers whatever they are; if IFC's delta
over the detector baseline is small (because the detectors already catch most
direct attacks), say so — IFC's value is the INDIRECT-injection class, which the
suite may or may not exercise heavily. That's a finding, not a failure.
