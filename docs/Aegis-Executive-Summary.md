# Aegis - Stopping LLM Agents from Damaging Production Systems

**Executive briefing - 5 June 2026**

Aegis prevents an LLM agent from taking an action that harms a production system. It sits between the model and the things it can touch - the shell, the network, and the kdb+ data store - and makes a deterministic allow / block / human-approval decision on every action, before the action runs. The model cannot talk its way past it.

---

## 1. The problem: an LLM with tools can break production

Give an LLM agent the ability to run commands and query data, and a single wrong tool call can:

- drop or delete a kdb+ table, or run an unbounded query that pulls an entire HDB into memory and stalls the tickerplant during market hours;
- exfiltrate client positions, P&L, or other classified data to an outside host;
- delete files, force-push, or touch a production system it was never meant to reach.

Prompt injection makes it worse: instructions hidden in data the agent reads (a document, a ticket, a market-data row) can hijack the model into issuing exactly such a call. Telling the model "do not do that" is advice it can ignore. The control must live OUTSIDE the model and decide BEFORE the action executes.

---

## 2. How Aegis stops it - two enforcement points the LLM cannot bypass

### A. The tool-use gate (our enforcement engine)

Every time the LLM goes to use a tool - run a command, write a file, call an MCP tool, execute a query - a hook fires and our engine decides **allow / block / require-human-approval before the action executes**. The engine, not the model, decides whether the action happens.

- **In Claude Code**, it runs as a PreToolUse hook on every tool call.
- **Via any model API** (Anthropic, OpenAI, Bedrock), a broker intercepts each tool the model requests before the application executes it. The model can only ever *request* an action; our broker decides whether to run it.
- **In production**, the engine runs as an out-of-process service (a "policy decision point") that the agent's own process cannot tamper with. If that service is unreachable, every action is denied (fail-closed).

The engine is **default-deny**: the agent can do only what the security team explicitly granted - a specific set of tools, shell commands, writable paths, network destinations, and queryable tables. Anything else is blocked by construction, which defeats obfuscation and "laundering" tricks that fool denylists. The policy is a signed file owned by the control function; because it is cryptographically signed and mounted read-only, the agent cannot edit or forge its own guardrails. Each MCP server is treated as zero-privilege until a manifest explicitly grants it tools, so a compromised tool server cannot reach beyond its declared scope.

### B. The kdb+ proxy (the interface between the agent / MCP and the production kdb+ system)

The agent never gets a direct handle to kdb+. Its queries pass through our **query proxy**, which sits between the MCP / agent layer and the kdb+ data store and enforces on the REAL query text:

- it **parses** the q / SQL;
- it **injects a date-partition filter and a row cap**, so a full-table scan cannot pull an entire HDB into memory and stall the tickerplant - e.g. an unbounded "select from trade" is rewritten to a bounded, date-filtered, row-capped query before kdb+ ever sees it;
- it **blocks mutations** (delete / drop / update) - the interface is read-only by default;
- it **rejects** queries against tables not on the allowlist, and anything it cannot safely parse (fail-closed).

So the kdb+ production system only ever receives a bounded, read-only, allowlisted query. A runaway or destructive query physically cannot reach it. A matching **egress proxy** sits between the agent and the network and blocks exfiltration of classified data even to an otherwise-allowlisted host.

### What actually gets stopped (worked examples)

- A "delete from trade" / drop-table request -> BLOCKED (mutation; read-only interface).
- An unbounded "select from quote" -> REWRITTEN to a bounded, date-filtered, row-capped query before kdb+ runs it.
- A request to upload positions data to an external host -> BLOCKED (egress + classified-data).
- A query aimed at the production tickerplant -> BLOCKED (production target).
- The agent trying to edit its own policy or a protected file -> BLOCKED.

Every one of these decisions is written to a tamper-proof audit log (hash-chained, mirrored off-host, and anchored so deletion or truncation is detectable) - the regulator-facing record of what the agent tried and what was allowed.

---

## 3. Why it cannot be ignored

- **The decision is outside the model's control loop** - made by a separate process before the tool runs; the model's output is only an input to the gate.
- **Default-deny** - the agent can only do what was explicitly granted; ungranted actions fail by construction.
- **Fail-closed everywhere** - missing or forged policy, unreachable engine, unknown tool, or any internal error results in BLOCK, never a silent allow.
- **Signed policy** - the agent cannot disable or rewrite its own guardrails.
- **Proven, not asserted** - 15 of 15 automated checks pass from a single command; the core property (the agent can never exceed its grants) is established by an exhaustive formal proof; and it has been demonstrated gating a real model call live.

---

## 4. How this compares to the industry (supporting context)

The field has independently converged on exactly this approach - deterministic, out-of-process, default-deny enforcement that does not trust the model. Classifier-style "content guardrails" have been shown evadable up to 100% (arXiv:2504.11168); standards bodies (CoSAI / OASIS, OWASP) now state plainly: never rely on the LLM for security-critical validation.

Production controls split into three planes, and no single competitor spans all of them: content filtering (e.g. AWS Bedrock Guardrails), tool-call authorization (e.g. AWS Cedar / AgentCore - deterministic, formally verified), and the data / query plane (e.g. Satori, Immuta - which rewrite SQL queries to inject row filters). Aegis's differentiation is unifying the tool-use gate, the query plane, network egress, signed audit, and confinement into one default-deny pipeline for the agent - and doing the query-plane interface for **kdb+ / q**, which the SQL-oriented data-governance proxies do not support.

---

## 5. Compliance posture (primary-source verified)

- **EU AI Act** (binding for high-risk systems) maps directly onto Aegis controls: Art. 12 automatic event logging -> the tamper-proof audit; Art. 14 human oversight -> the require-approval path with override / stop; Art. 15 robustness and cybersecurity (resilience against unauthorised alteration, data / model poisoning, adversarial inputs) -> the red-team-tested, signed, fail-closed gate.
- **US bank model-risk:** SR 26-2 (Apr 2026) supersedes SR 11-7 and places generative / agentic AI OUTSIDE formal model-risk-management scope - so Aegis is positioned not as MRM compliance, but as the operational risk-management and governance control the guidance still expects for such tools.

---

## 6. Status and honest limitations

- Implemented and tested today: the tool-use gate engine, the kdb+ query proxy, the egress proxy, MCP per-server manifests, signed policy, tamper-proof audit, confinement validation, formal proof, and the assurance suite - 15/15 core checks green.
- Aegis governs agent ACTIONS. It does not make the model truthful and does not replace the bank's existing identity, data-loss-prevention, or change-control systems; it composes with them.
- Guarantee by surface: containerised operational agents get the strongest (watertight) posture; developer laptops get strong defense-in-depth, since a laptop cannot be fully sandboxed.
- Planned: an official end-to-end adversarial benchmark run, a stronger (machine-checked) formal proof, and production audit-sink and human-approval back-ends.

*Prepared from two adversarially-verified research passes plus primary-source verification. Not legal advice; validate regulatory mappings with your control function.*
