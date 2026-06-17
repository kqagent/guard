# Aegis — the live web demo

One server, one page, six capabilities — Aegis governing a real LLM-agent query
surface **live against a real kdb+ HDB**, nothing pre-recorded. This is the
single, client-presentable consolidation of the earlier scattered demos
(`pilot/realism/demo_server.py`, `demo_web.html`, `demo_should_shouldnt.py`,
`DEMO_should_shouldnt.md` — all retired in favour of this).

## Run

```bash
cd ~/guard
QHOME=/opt/kdb/4.1/2024.10.16 QLIC=/opt/kdb/QLIC \
    .venv/bin/python pilot/demo/demo_app.py
# then open http://localhost:8012/
```

The server starts a read-only q HDB process on port 8013, signs the policy at
startup, and serves the page on 8012. `Ctrl-C` stops both. Requirements: the q
binary at `/opt/kdb/4.1/2024.10.16/l64/q` and the demo HDB at
`~/aegis-hdb/fsp1/hdb` (50 daily partitions, ~10M rows each → ~500M rows on this
node; the full estate is ~4B). No API key needed — every result is deterministic
and computed live.

## What it shows

Each panel shows the same four things in sequence:
**agent request → Aegis decision → the exact q that runs (or the rejection +
which layer caught it) → the real result / row count from the live HDB**, with a
one-line plain-English caption.

1. **Structured query** — the compiler emits bounded, **date-first**, capped,
   entitlement-filtered q from a structured request; real rows with honest
   timing (the as-of join is genuinely heavy, ~40s, shown as-is).
2. **Row-level entitlements** — `analyst-equities` asks for GOOG & NVDA; the
   compiled q carries **both** the agent filter **and** the mandatory
   `sym in AAPL,MSFT` entitlement → 0 rows. The entitlement cannot be widened.
3. **Free-form q** — a hand-written query is **lifted and RECOMPILED** through
   the same compiler (allowlist-on-parse); the raw q is never executed. Includes
   a **date-second → date-first** normalisation (no full-partition scan) and
   dangerous / off-allowlist queries rejected, each naming **which layer** caught
   it: the **lifter** (not in the safe subset — no request ever formed) or the
   **compiler** (lifted, but fails the table/column/date allowlist).
4. **Safety + resource** — mutations are **inexpressible** (no verb in the
   grammar; the lifter rejects them), a would-be unbounded scan is **bounded by
   the materialisation cap** (`i<1,000,000`) so it cannot OOM the box, and the
   structured route also sanitises injected values/identifiers and enforces the
   span cap + default-deny.
5. **Injection defence (IFC)** — an action derived from untrusted tool output is
   blocked before a privileged sink; the same action from trusted input is
   allowed. Deterministic and content-independent (labels JOIN; untrusted wins).
6. **The record** — the **signed policy** (flip one byte → verification fails →
   gate fails closed) and a **WORM, hash-chained audit line per decision** (every
   panel you trigger appends one; the chain + external anchor are verified live).
   The gate runs out-of-process behind OS confinement — the agent's only wire out
   is the gate's decision.

## How it's wired

Both query routes go through the **one chokepoint**, `aegis.query_gate.QueryGate`:

- the **structured** tool (`run_structured_query`) → `compiler.compile(request)`
- the **free-form** tool (`run_query`) → `freeform_q.compile_freeform` (lift +
  recompile through the same compiler)

Both return only the trusted compiler's bounded, date-filtered,
entitlement-injected q — or raise, fail-closed. Set `allow_freeform=False` on the
gate to turn the free-form route off entirely (structured-only — the safest
posture).

Policy: `pilot/realism/policy.realism.demo.json` (column allowlist derived from
`meta` on the real tables, plus the row-entitlement and span-cap controls).
Audit artifacts are written under `pilot/demo/.aegis-demo/` (git-ignored).
