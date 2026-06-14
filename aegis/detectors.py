"""Threat packs — the dos and don'ts, as deterministic detectors.

Each detector is a pure function: (Action, policy) -> [Finding]. Same input,
same output, every time — the decision never depends on an LLM. Pattern
lists and config are read from the policy bundle so the control function
tunes them without touching code; structural logic (host extraction, RBAC,
statement parsing) lives here because it's more than a regex.

Add a pack: write a function, register it in DETECTORS, name it in
policy["enabled_packs"].

Packs:
    secrets          credentials in code / commands / prompts
    exfiltration     data egress to non-allowlisted destinations
    pii_egress       *classified* data leaving (data-classification aware)
    destructive_ops  irreversible / wide-blast-radius mutations
    prod_protection  production targets + the guardrails themselves
    resource_guard   runaway queries/loops that can degrade prod systems
    rbac             per-principal tool authorization (default-deny capable)
    command_allowlist default-deny shell: only approved binaries run
    cost_budget      per-principal daily action/cost ceilings (reads the
                     budget ledger; charging is the execution layer's job)
"""

from __future__ import annotations

import re

from .model import Action, Effect, Finding


def _effect(cfg: dict, default: str) -> Effect:
    return Effect(cfg.get("effect", default))


def _mask(secret: str) -> str:
    if len(secret) <= 4:
        return "****"
    return secret[:2] + "*" * (len(secret) - 4) + secret[-2:]


# ===========================================================================
# secrets
# ===========================================================================

_SECRET_PATTERNS = [
    ("aws-access-key", r"AKIA[0-9A-Z]{16}"),
    ("aws-secret-key", r"(?i)aws_secret_access_key\s*[:=]\s*[\"']?([A-Za-z0-9/+]{40})"),
    ("gcp-api-key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("gcp-sa-key", r"\"private_key_id\"\s*:\s*\"[0-9a-f]{40}\""),
    ("azure-conn", r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+"),
    ("private-key-block", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ("slack-token", r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    ("github-token", r"gh[pousr]_[0-9A-Za-z]{20,}"),
    ("stripe-key", r"sk_live_[0-9A-Za-z]{20,}"),
    ("jwt", r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    ("bearer-token", r"(?i)authorization\s*:\s*bearer\s+[A-Za-z0-9._\-]{12,}"),
    ("generic-assignment",
     r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\b"
     r"\s*[:=]\s*[\"']?([^\s\"';]{6,})"),
    ("conn-string-creds", r"(?i)(?:jdbc|postgres|postgresql|mysql|mongodb)://[^:\s]+:([^@\s]{4,})@"),
]


def detect_secrets(action: Action, policy: dict) -> list[Finding]:
    cfg = policy.get("secrets", {})
    eff = _effect(cfg, "block")
    text = action.searchable_text()
    findings: list[Finding] = []
    for name, pat in _SECRET_PATTERNS:
        for m in re.finditer(pat, text):
            captured = m.group(1) if m.groups() else m.group(0)
            findings.append(Finding(
                rule_id=f"SEC-{name.upper()}",
                effect=eff,
                pack="secrets",
                reason=f"possible {name} in {action.surface} action",
                remediation="Reference secrets via a vault/secret-manager handle, never inline.",
                evidence=_mask(captured),
            ))
    return findings


# ===========================================================================
# exfiltration
# ===========================================================================

_EGRESS_TOOLS = re.compile(r"\b(curl|wget|nc|ncat|telnet|scp|sftp|rsync|ssh)\b", re.IGNORECASE)
_PY_EGRESS = re.compile(r"\b(requests\.(get|post|put)|urllib\.request|httpx\.)", re.IGNORECASE)
_CLOUD_UP = re.compile(r"(?i)\b(aws\s+s3\s+cp|aws\s+s3\s+sync|gsutil\s+cp|az\s+storage\s+blob\s+upload)\b")
_MAIL = re.compile(r"(?i)\b(sendmail|mailx|mutt|smtplib|ssmtp)\b")
_DEV_TCP = re.compile(r"/dev/tcp/([^/\s]+)")
_URL_HOST = re.compile(r"https?://([^/\s'\"]+)")
_SSH_HOST = re.compile(r"\b(?:scp|sftp|ssh|rsync)\b[^\n]*?\b[\w.-]+@([\w.-]+)")


def _egress_intent(text: str) -> bool:
    return bool(_EGRESS_TOOLS.search(text) or _PY_EGRESS.search(text)
                or _DEV_TCP.search(text) or _CLOUD_UP.search(text) or _MAIL.search(text))


def _hosts(text: str) -> list[str]:
    hosts: list[str] = []
    for rx in (_URL_HOST, _SSH_HOST, _DEV_TCP):
        for m in rx.finditer(text):
            hosts.append(m.group(1).split(":")[0].lower())
    return hosts


def detect_exfiltration(action: Action, policy: dict) -> list[Finding]:
    cfg = policy.get("egress", {})
    allow = {h.lower() for h in cfg.get("allowlist_hosts", [])}
    eff = _effect(cfg, "block")
    text = action.searchable_text()
    if not _egress_intent(text):
        return []
    hosts = _hosts(text)
    findings: list[Finding] = []
    offending = [h for h in hosts if h not in allow]
    if offending:
        for h in sorted(set(offending)):
            findings.append(Finding(
                rule_id="EXF-EGRESS-HOST", effect=eff, pack="exfiltration",
                reason=f"network egress to non-allowlisted host '{h}'",
                remediation="Route through the approved internal proxy / allowlist the host in policy.",
                evidence=h,
            ))
    elif not hosts:
        findings.append(Finding(
            rule_id="EXF-EGRESS-OPAQUE", effect=Effect.REQUIRE_APPROVAL, pack="exfiltration",
            reason="network egress with an unresolved destination",
            remediation="Make the destination explicit so it can be checked against the allowlist.",
        ))
    return findings


# ===========================================================================
# pii_egress — data-classification-aware: classified data must not leave
# ===========================================================================

def detect_pii_egress(action: Action, policy: dict) -> list[Finding]:
    cfg = policy.get("pii_egress", {})
    eff = _effect(cfg, "block")
    terms = cfg.get("sensitive_terms", [])
    text = action.searchable_text()
    if not _egress_intent(text):
        return []
    hits = [t for t in terms if re.search(rf"(?i)\b{re.escape(t)}\b", text)]
    if not hits:
        return []
    return [Finding(
        rule_id="PII-EGRESS", effect=eff, pack="pii_egress",
        reason=f"egress action references classified data ({', '.join(hits[:3])})",
        remediation="Classified data may not leave via agent actions; use the approved data-transfer pipeline.",
        evidence=hits[0],
    )]


# ===========================================================================
# destructive_ops
# ===========================================================================

_DESTRUCTIVE = [
    ("rm-recursive-force", r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|-rf|-fr)\b"),
    ("rm-glob", r"\brm\s+(-[a-zA-Z]+\s+)?[^\s|;&]*\*"),
    ("git-force-push", r"\bgit\s+push\b[^\n]*?(--force\b|-f\b|--force-with-lease\b)"),
    ("git-hard-reset", r"\bgit\s+reset\s+--hard\b"),
    ("git-clean", r"\bgit\s+clean\s+-[a-zA-Z]*f"),
    ("sql-drop", r"(?i)\bdrop\s+(table|database|schema|index)\b"),
    ("sql-truncate", r"(?i)\btruncate\s+table\b"),
    ("sql-delete-unbounded", r"(?i)\bdelete\s+from\s+\w+\s*(;|$)"),
    ("q-delete", r"\bdelete\s+from\s+`?\w+"),
    ("q-hdel", r"\bhdel\b"),
    ("disk-wipe", r"\b(mkfs|dd\s+if=|shred|wipefs)\b"),
    ("recursive-chmod-chown", r"\bch(mod|own)\s+-R\b"),
    ("chmod-777", r"\bchmod\s+(-[a-zA-Z]+\s+)?0?777\b"),
    ("kill-signal", r"\b(kill\s+-9|pkill|killall)\b"),
    ("service-stop", r"(?i)\bsystemctl\s+(stop|disable|mask)\b"),
    ("firewall-flush", r"\biptables\s+-F\b"),
    ("crontab-wipe", r"\bcrontab\s+-r\b"),
    ("docker-prune", r"(?i)\bdocker\s+(system\s+prune|rm\s+-f|volume\s+rm)\b"),
    ("k8s-delete", r"(?i)\bkubectl\s+delete\b"),
]


def detect_destructive(action: Action, policy: dict) -> list[Finding]:
    cfg = policy.get("destructive", {})
    eff = _effect(cfg, "block")
    text = action.searchable_text()
    findings: list[Finding] = []
    for name, pat in _DESTRUCTIVE:
        m = re.search(pat, text)
        if m:
            findings.append(Finding(
                rule_id=f"DST-{name.upper()}", effect=eff, pack="destructive_ops",
                reason=f"destructive / irreversible operation ({name})",
                remediation="Scope the operation, take a backup, or route via change-control.",
                evidence=m.group(0)[:80],
            ))
    return findings


# ===========================================================================
# prod_protection
# ===========================================================================

def detect_prod_protection(action: Action, policy: dict) -> list[Finding]:
    cfg = policy.get("prod", {})
    eff = _effect(cfg, "block")
    findings: list[Finding] = []
    haystacks = [h for h in (action.command, action.file_path, action.content) if h]
    blob = "\n".join(haystacks)

    for pat in cfg.get("patterns", []):
        if re.search(pat, blob):
            findings.append(Finding(
                rule_id="PRD-TARGET", effect=eff, pack="prod_protection",
                reason=f"action references a production target (/{pat}/)",
                remediation="Production changes must go through change-control, not an agent.",
                evidence=pat,
            ))
            break

    for prot in policy.get("protected_paths", []):
        norm = prot.replace("\\", "/").lower()
        for h in haystacks:
            if norm in h.replace("\\", "/").lower():
                findings.append(Finding(
                    rule_id="PRD-PROTECTED-PATH", effect=Effect.BLOCK, pack="prod_protection",
                    reason=f"action touches a protected path ('{prot}') — including the guardrails themselves",
                    remediation="Protected paths are owned by the control function and are read-only to agents.",
                    evidence=prot,
                ))
                break
    return findings


# ===========================================================================
# resource_guard
# ===========================================================================

def detect_resource_guard(action: Action, policy: dict) -> list[Finding]:
    cfg = policy.get("resource_guard", {})
    eff = _effect(cfg, "require_approval")
    big_tables = cfg.get("big_tables", [])
    text = action.searchable_text()
    findings: list[Finding] = []

    for tbl in big_tables:
        for m in re.finditer(rf"(?i)\bselect\b(.*?)\bfrom\s+`?{re.escape(tbl)}\b(.*?)(?:;|$)", text, re.DOTALL):
            stmt = m.group(0)
            bounded = bool(re.search(r"(?i)\bwhere\b.*\bdate\b", stmt)
                           or re.search(r"(?i)\blimit\b", stmt)
                           or re.search(r"\bsublist\b", stmt)
                           or re.search(r"^\s*\d+\s*#", stmt)
                           # Partition-enumeration metadata query: `select distinct date
                           # from t` returns the (tiny, bounded) set of partitions, not
                           # rows. Analysts run it constantly to discover coverage; it is
                           # not an unbounded scan. Narrow on purpose — `select date ...`
                           # (without distinct) still reads every row and stays flagged.
                           or re.search(r"(?i)\bselect\s+distinct\s+date\b", stmt))
            if not bounded:
                findings.append(Finding(
                    rule_id="RES-UNBOUNDED-SCAN", effect=eff, pack="resource_guard",
                    reason=f"unbounded scan of large table '{tbl}' (no date filter / row limit)",
                    remediation="Add a `where date=...` partition filter and/or a row limit before running.",
                    evidence=stmt.strip()[:80],
                ))
                break

    # Obvious infinite loops in q / shell.
    if re.search(r"\bwhile\s*\[\s*1[bj]?\s*;", text) or re.search(r"\bwhile\s+true\b", text):
        findings.append(Finding(
            rule_id="RES-INFINITE-LOOP", effect=eff, pack="resource_guard",
            reason="apparent unbounded loop (while[1] / while true)",
            remediation="Bound the loop with a termination condition.",
        ))
    return findings


# ===========================================================================
# rbac — per-principal tool authorization (opt-in; default-deny capable)
# ===========================================================================

def detect_rbac(action: Action, policy: dict) -> list[Finding]:
    cfg = policy.get("rbac", {})
    principals = cfg.get("principals", {})
    p = action.principal or "unknown"
    rule = principals.get(p) or principals.get("*")
    if rule is None:
        if cfg.get("default_deny"):
            return [Finding(
                rule_id="RBAC-UNPROVISIONED", effect=Effect.BLOCK, pack="rbac",
                reason=f"principal '{p}' is not provisioned in policy (default-deny)",
                remediation="Add the principal to rbac.principals with an explicit tool grant.",
            )]
        return []
    allow = rule.get("allow_tools")
    deny = rule.get("deny_tools", [])
    if action.tool in deny or (allow is not None and action.tool not in allow):
        return [Finding(
            rule_id="RBAC-TOOL-DENIED", effect=Effect.BLOCK, pack="rbac",
            reason=f"principal '{p}' is not authorized to use tool '{action.tool}'",
            remediation="Grant the tool in rbac.principals or have an authorized principal act.",
        )]
    return []


# ===========================================================================
# command_allowlist — default-deny shell (opt-in)
# ===========================================================================

def detect_command_allowlist(action: Action, policy: dict) -> list[Finding]:
    cfg = policy.get("command_allowlist", {})
    if action.command is None:
        return []
    allowed = set(cfg.get("binaries", []))
    eff = _effect(cfg, "require_approval")
    # First token of each pipeline segment is the binary.
    segments = re.split(r"[|;&]+", action.command)
    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        binary = re.split(r"\s+", seg)[0].split("/")[-1]
        if binary and binary not in allowed:
            return [Finding(
                rule_id="CMD-NOT-ALLOWLISTED", effect=eff, pack="command_allowlist",
                reason=f"command '{binary}' is not on the allowlist (default-deny)",
                remediation="Add the binary to command_allowlist.binaries if it is approved.",
                evidence=binary,
            )]
    return []


# ===========================================================================
# kdb_code_quality — bridge to THIS project's existing hard gate (opt-in)
# ===========================================================================

def detect_kdb_lint(action: Action, policy: dict) -> list[Finding]:
    """Run this repo's `tools/gate.js` (the maze kdb hard gate, 53 rules) as
    a detector pack. Fires only on coding actions targeting q files, so the
    existing engine is used for exactly what it is good at — q code quality —
    under the Aegis umbrella.

    Note: unlike the security packs, this one shells out to Node (the engine
    is JS). It keeps the existing engine's baseline-diff semantics (block on
    NEW violations beyond baseline), which is correct for code quality. The
    security packs stay zero-dependency and absolute-block.
    """
    import json
    import shutil
    import subprocess
    from pathlib import Path

    if action.surface != "coding":
        return []
    fp = action.file_path or ""
    if not fp.endswith((".q", ".k", ".quke")):
        return []

    cfg = policy.get("kdb_code_quality", {})
    fail_eff = _effect(cfg, "block")  # if Node/engine unavailable, fail closed
    repo_root = Path(__file__).resolve().parent.parent
    gate_js = cfg.get("gate_js") or str(repo_root / "tools" / "gate.js")
    cwd = action.cwd or cfg.get("project_root") or str(repo_root)

    node = shutil.which("node")
    if node is None or not Path(gate_js).exists():
        return [Finding(
            rule_id="KDBQ-ENGINE-UNAVAILABLE", effect=fail_eff, pack="kdb_code_quality",
            reason="kdb hard-gate engine unavailable (Node or gate.js missing) — failing closed",
            remediation="Install Node and ensure tools/gate.js is present, or disable this pack.",
        )]

    try:
        proc = subprocess.run(
            [node, gate_js, cwd, fp, "--stdin"],
            input=action.content or "",
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=cfg.get("timeout_seconds", 15),
        )
    except Exception as e:
        return [Finding(
            rule_id="KDBQ-ENGINE-ERROR", effect=fail_eff, pack="kdb_code_quality",
            reason=f"kdb hard-gate engine raised {type(e).__name__} — failing closed",
        )]

    if proc.returncode == 2:  # infrastructure error from gate.js
        return [Finding(
            rule_id="KDBQ-ENGINE-ERROR", effect=fail_eff, pack="kdb_code_quality",
            reason=f"kdb hard-gate infrastructure error: {proc.stdout.strip()[:160]}",
        )]

    try:
        result = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return [Finding(
            rule_id="KDBQ-ENGINE-ERROR", effect=fail_eff, pack="kdb_code_quality",
            reason="kdb hard-gate returned unparseable output — failing closed",
        )]

    if result.get("blocked"):
        return [Finding(
            rule_id="KDBQ-LINT-BLOCK", effect=Effect.BLOCK, pack="kdb_code_quality",
            reason=(result.get("reason") or "kdb lint block").splitlines()[0],
            remediation="Fix the q lint violation reported by the maze gate.",
            evidence=(result.get("reason") or "")[:200],
        )]
    return []


# ===========================================================================
# tool_rules — argument-level policy on NAMED tools (function-calling agents)
# ===========================================================================

def detect_tool_rules(action: Action, policy: dict) -> list[Finding]:
    """Gate named function-tools (send_money, send_email, post_webpage, …) by
    a per-tool rule, optionally conditioned on a regex over the call's
    arguments. This is the structured-tool analogue of the shell detectors —
    the direction Progent/PCAS formalize (rules over tool names + arguments).

    policy.tool_rules.rules = {
        "<tool>": {"effect": "block|require_approval",
                    "block_if": "<regex over args, optional>",
                    "reason": "...", "remediation": "..."}}
    A rule with no `block_if` always applies its effect; with `block_if`, it
    applies only when the arguments match.
    """
    rules = policy.get("tool_rules", {}).get("rules", {})
    r = rules.get(action.tool)
    if not r:
        return []
    block_if = r.get("block_if")
    if block_if and not re.search(block_if, action.searchable_text(), re.IGNORECASE):
        return []
    return [Finding(
        rule_id=f"TOOL-RULE-{action.tool.upper()}",
        effect=_effect(r, "block"),
        pack="tool_rules",
        reason=r.get("reason", f"named tool '{action.tool}' is gated by policy"),
        remediation=r.get("remediation", "Adjust policy.tool_rules if this call is approved."),
    )]


# ===========================================================================
# cost_budget — per-principal daily ceilings (aggregate resource guard)
# ===========================================================================

def detect_cost_budget(action: Action, policy: dict) -> list[Finding]:
    """Veto actions from a principal that has exhausted its daily budget.

    Pure read: the ledger file is part of the detector's input; spend is
    recorded by the execution layer (sdk.AegisSession) after the tool
    actually runs. An unverifiable ledger fails closed — a spend that
    cannot be checked against its budget is not authorized.
    """
    from .budget import LedgerError, limits_for, over_budget

    cfg = policy.get("cost_budget", {})
    eff = _effect(cfg, "require_approval")
    principal = action.principal or "unknown"
    if limits_for(principal, cfg) is None:
        return []
    try:
        over, why = over_budget(principal, cfg)
    except LedgerError as e:
        return [Finding(
            rule_id="BUDGET-LEDGER-UNAVAILABLE", effect=eff, pack="cost_budget",
            reason=f"budget ledger cannot be verified ({e}) — failing closed",
            remediation="Restore the ledger file named in policy.cost_budget.ledger.",
        )]
    if not over:
        return []
    return [Finding(
        rule_id="BUDGET-EXHAUSTED", effect=eff, pack="cost_budget",
        reason=f"principal '{principal}' is over its daily budget ({why})",
        remediation="Raise the limit in policy.cost_budget.limits or wait for the daily reset.",
        evidence=why,
    )]


# ===========================================================================
# mcp_manifest — per-MCP-server capability manifests (AgentBound-style)
# ===========================================================================

def detect_mcp_manifest(action: Action, policy: dict) -> list[Finding]:
    """Zero-privilege-by-default for MCP servers. A tool call arrives as
    `mcp__<server>__<tool>`; the server may only use tools its manifest
    explicitly declares. No manifest => the server has no privileges at all
    (default-deny). This mirrors AgentBound (FSE 2026): servers start with
    zero privilege and gain capability only via an explicit manifest.

    policy.mcp.manifests = {"<server>": {"allow_tools": ["...", "*"]}}
    """
    if not action.tool.startswith("mcp__"):
        return []
    cfg = policy.get("mcp", {})
    eff = _effect(cfg, "block")
    parts = action.tool.split("__")
    if len(parts) < 3 or not parts[1] or not parts[2]:
        return [Finding(
            rule_id="MCP-MALFORMED", effect=eff, pack="mcp_manifest",
            reason=f"malformed MCP tool id '{action.tool}' — failing closed",
            remediation="MCP tools must be named mcp__<server>__<tool>.",
        )]
    server, toolname = parts[1], "__".join(parts[2:])
    manifest = cfg.get("manifests", {}).get(server)
    if manifest is None:
        return [Finding(
            rule_id="MCP-UNPROVISIONED", effect=Effect.BLOCK, pack="mcp_manifest",
            reason=f"MCP server '{server}' has no manifest — zero-privilege default-deny",
            remediation="Declare the server in policy.mcp.manifests with an allow_tools list.",
        )]
    allow = manifest.get("allow_tools", [])
    if toolname not in allow and "*" not in allow:
        return [Finding(
            rule_id="MCP-UNDECLARED", effect=eff, pack="mcp_manifest",
            reason=f"tool '{toolname}' is not declared in the '{server}' MCP manifest",
            remediation="Add the tool to the server's manifest if it is approved.",
        )]
    return []


# Registry: pack name -> detector. Engine runs only enabled packs.
def detect_kdb_guard(action: Action, policy: dict) -> list[Finding]:
    """Gate-layer defense-in-depth for the q/kdb surface: flag OS/file/eval/
    handler builtins (system, hopen, hdel, set/save, value/eval, .z.*, exit,
    amend, mutations) in a kdb query. Scoped to query tools ONLY (configurable
    `query_tools`) so the q-specific deny-list never false-positives on a Bash
    `--get`/`set`/`system` token. The QueryGuard proxy is the ground-truth veto
    on the DB-bound query; this is the independent gate-layer check for any tool
    that carries q, and the audit finding."""
    from .query_proxy import _DANGEROUS_Q  # single source of truth
    cfg = policy.get("kdb_guard", {})
    eff = _effect(cfg, "block")
    tools = set(cfg.get("query_tools", ["run_query", "run_q", "qcmd", "query", "exec_q", "kdb_query"]))
    if action.tool not in tools:
        return []
    q = ""
    for key in ("query", "q", "code", "expr"):
        v = action.tool_input.get(key)
        if isinstance(v, str) and v:
            q = v
            break
    if not q:
        q = " ".join(str(v) for v in action.tool_input.values() if isinstance(v, str))
    low = q.lower()
    for rule, pat in _DANGEROUS_Q:
        if re.search(pat, low):
            return [Finding(
                rule_id=f"KDB-{rule}", effect=eff, pack="kdb_guard",
                reason=f"dangerous q/kdb construct ({rule}) in a query — OS/file/eval/handler access",
                remediation="kdb agents may only run read queries on allowlisted tables; "
                            "system/file/eval/connection builtins are denied.",
                evidence=q.strip()[:80],
            )]
    return []


# ===========================================================================
# file_access — allowlist discipline for file-READ tools (file-plane twin of
# query_proxy.allowed_tables). Found necessary by the FSP pilot: read_file was
# gated by a deny-list (protected_paths), so a model probing positions.csv/
# pnl.csv was ALLOWED and only the file's absence prevented a leak. The lesson
# generalised: every tool the agent holds needs enumerate-goodness, not just the
# query tool. A read tool may read ONLY paths under readable_paths; else block.
# ===========================================================================

def _path_under(file_path: str, prefix: str) -> bool:
    fp = file_path.replace("\\", "/").lstrip("./")
    pref = prefix.replace("\\", "/").rstrip("/").lstrip("./")
    return fp == pref or fp.startswith(pref + "/")


def detect_file_access(action: Action, policy: dict) -> list[Finding]:
    cfg = policy.get("file_access", {})
    eff = _effect(cfg, "block")
    read_tools = set(cfg.get("read_tools", ["read_file", "Read"]))
    if action.tool not in read_tools:
        return []
    path = action.file_path  # tool_input file_path | path
    if not path or not isinstance(path, str):
        return [Finding(
            rule_id="FILE-NO-PATH", effect=eff, pack="file_access",
            reason="file read with no resolvable path — failing closed",
            remediation="Pass an explicit file path under an allowlisted readable directory.",
        )]
    readable = cfg.get("readable_paths")
    if readable is None:
        return [Finding(
            rule_id="FILE-NO-ALLOWLIST", effect=eff, pack="file_access",
            reason="file_access enabled but no readable_paths configured — failing closed",
            remediation="Set policy.file_access.readable_paths to the directories the agent may read.",
        )]
    if not any(_path_under(path, p) for p in readable):
        return [Finding(
            rule_id="FILE-READ-NOT-ALLOWLISTED", effect=eff, pack="file_access",
            reason=f"read of '{path}' is not under an allowlisted readable path",
            remediation="Add the directory to policy.file_access.readable_paths if approved.",
            evidence=path,
        )]
    return []


DETECTORS = {
    "secrets": detect_secrets,
    "kdb_guard": detect_kdb_guard,
    "file_access": detect_file_access,
    "exfiltration": detect_exfiltration,
    "pii_egress": detect_pii_egress,
    "destructive_ops": detect_destructive,
    "prod_protection": detect_prod_protection,
    "resource_guard": detect_resource_guard,
    "rbac": detect_rbac,
    "command_allowlist": detect_command_allowlist,
    "kdb_code_quality": detect_kdb_lint,
    "tool_rules": detect_tool_rules,
    "mcp_manifest": detect_mcp_manifest,
    "cost_budget": detect_cost_budget,
}
