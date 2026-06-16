# Aegis - Technology Glossary

*A plain-English decoder for the names in the Aegis setup. The reassuring point:
almost none of this is exotic - Ed25519, namespaces, Landlock, seccomp, Z3, Cedar
are standard, battle-tested components. We did not invent cryptography or sandboxing.
The two original pieces are the **query compiler** (the AI fills a form, we write the
safe query) and wiring **information-flow control** onto a kdb+ agent. Everything else
is well-understood parts assembled into one fail-closed, signed, audited gate.*

---

### What we're protecting

| Name | What it is / does |
|---|---|
| **kdb+** | The database itself - a very fast database banks use for huge volumes of market data and trades. |
| **q** | The language you talk to kdb+ in. Extremely powerful (a full programming language) - which is the whole problem: the same language that asks "average price" can also delete data or run OS commands. |
| **HDB** | "Historical database" - the on-disk pile of past data, split by date. |

### The gatekeeper (the core gate)

| Name | What it is / does |
|---|---|
| **PDP (Policy Decision Point)** | Jargon for "the gatekeeper": the separate program that says yes/no to every action. |
| **Query compiler** | Takes the AI's structured *form* and writes the safe q itself. The "AI never writes code" piece. *(The genuinely novel bit.)* |
| **Detector packs** | Pattern scanners (secrets, personal data, destructive commands) that act as a backup veto. |
| **Egress proxy** | "Egress" = outbound network traffic. A checkpoint all outbound traffic must pass; only approved destinations are allowed and the payload is inspected. Stops data being smuggled out. |

### The AI-specific defences

| Name | What it is / does |
|---|---|
| **IFC (Information-Flow Control)** | The "trusted vs untrusted" tagging that stops prompt injection. Tracks where each piece of data *came from* and blocks untrusted data from triggering a dangerous action. |
| **Row-level entitlements** | Per-person row filters - which rows each user may see, stapled onto every query, non-removable. |
| **RBAC** | "Role-Based Access Control" - standard "permissions by job role." Off-the-shelf concept. |

### Making the rulebook un-forgeable + keeping records

| Name | What it is / does |
|---|---|
| **Ed25519** | A standard digital-signature algorithm. Signs the rulebook so the AI can't forge or edit it - like a wax seal only the control function can make and anyone can verify. |
| **WORM (Write Once Read Many)** | A log you can add to but never edit or delete. The tamper-evident audit trail. |
| **Hash-chain** | Each log entry carries a fingerprint of the one before it, so quietly altering or deleting an entry breaks the chain and is detectable. |

### The cage (operating-system confinement - all standard Linux features)

| Name | What it is / does |
|---|---|
| **Namespaces** | A Linux feature giving the AI its own private view of the machine (its own files, network, process list) so it can't see or touch anything else. The cell walls. |
| **Landlock** | A Linux security feature that lets a program lock itself to a specific allowed set of files, enforced by the kernel and irreversible. Limits which files the AI can reach. |
| **seccomp** | A Linux feature that filters which low-level system commands ("syscalls") a program may make. We block the dangerous ones (loading kernel code, debugging other processes, mounting disks). Shrinks the attack surface. |
| **rlimits / no-new-privs** | Resource caps (can't fork-bomb the box) and "can never gain more privileges than it started with." |

### The watchdog

| Name | What it is / does |
|---|---|
| **Supervisor / circuit-breaker / kill switch** | Watches the *stream* of actions and automatically quarantines and shuts the AI down if it starts misbehaving. |
| **Overseer** | A *second* AI that reads the logs and writes plain-English incident summaries. **Advisory only** - it never makes the security decision (you never want one AI guarding another as the real control). |

### Proving it's correct (the assurance layer)

| Name | What it is / does |
|---|---|
| **Z3 / SMT** | A mathematical theorem prover. Used to *prove* the rule-logic is sound (e.g. "an allowed action is always within granted permissions"), not just test it. |
| **Cedar** | Amazon's open-source permissions language + checker. Used as an independent second opinion on our rules. |
| **AgentDojo** | The industry-standard security exam for AI agents - a large set of attack scenarios researchers score systems against. |
| **MCP (Model Context Protocol)** | The emerging standard way AI agents plug into external tools. We have per-tool rules for it. |

---

*The one line: "We didn't invent crypto or sandboxing - those are standard parts. The
original work is the query compiler and the information-flow defence, assembled with the
rest into one fail-closed, signed, audited gate around the AI."*
