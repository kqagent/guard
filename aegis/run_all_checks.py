"""One-command acceptance suite — runs every Aegis battery and summarises.

    python -m aegis.run_all_checks

CORE checks are stdlib + cryptography only and must all pass. OPTIONAL checks
need extra infra (the kdb bridge needs Node + tools/gate.js); they're reported
but do not fail the suite when their dependency is absent.

Exit code is non-zero iff a CORE check fails — so this is the CI gate and the
"does it work?" proof you hand to a reviewer.
"""

from __future__ import annotations

import subprocess
import sys

CORE = [
    ("demo", "deterministic guardrail demo + fail-closed + audit tamper"),
    ("example_api_loop", "platform-API tool-loop gating (Anthropic/OpenAI shape)"),
    ("proxy", "input-side proxy: prompt redaction + model allowlist"),
    ("pdp_test", "out-of-process PDP sidecar + fail-closed when unreachable"),
    ("query_proxy_test", "kdb/SQL query proxy: parse, bound, reject"),
    ("query_compiler_test", "structured query compiler: allowlist, fail-closed, no dangerous output"),
    ("query_compiler_entitlements_test", "row-level entitlements: mandatory non-removable row filter + span cap"),
    ("file_access_test", "file-read allowlist (file-plane twin of query allowlist)"),
    ("egress_proxy_test", "network egress: host allowlist + SSRF + payload DLP"),
    ("egress_proxy_daemon_test", "egress forward-proxy daemon: forward/block/DLP/CONNECT tunnel"),
    ("signing_test", "Ed25519 policy signing; tamper/wrong-key/missing -> fail-closed"),
    ("confinement_test", "deployment hardening validator"),
    ("seccomp_test", "seccomp-bpf syscall deny-list: well-formed BPF + real kernel SIGSYS kill"),
    ("audit_worm_test", "tamper-proof audit: mirror + anchor truncation detection"),
    ("monitor", "monitor mode + false-positive / recall metrics"),
    ("formal", "exhaustive proof: default-deny soundness + monotonic confinement"),
    ("monotonic_confinement_test", "policy-update guard: narrowing auto / widening needs approval"),
    ("agentdojo_eval", "AgentDojo-aligned tool-call defense (model-independent)"),
    ("compliance", "regulatory crosswalk self-verified against runnable evidence"),
    ("mcp_test", "per-MCP-server manifests (AgentBound-style zero-privilege)"),
    ("redteam_corpus", "adversarial evasion corpus (catch-rate + coverage boundary)"),
    ("worm_sinks_test", "WORM audit sinks: syslog/HTTP/file/S3 + strict fail-closed"),
    ("approvals_test", "approval workflow: grant/deny/timeout, fail-closed silence"),
    ("budget_test", "per-principal daily action/cost ceilings, fail-closed ledger"),
    ("sdk_test", "broker SDK: gate -> approve -> execute -> charge composition"),
    ("cedar_export", "authz subset exported as Cedar text (interop + analysis)"),
    ("supervisor_test", "runtime supervisor: tripwires + circuit breaker + kill switch + incidents"),
    ("overseer_test", "LLM overseer (2nd line): reads logs, advisory verdict + incident narrative"),
    ("overseer_wiring_test", "overseer wired advisory-only: narrative attached, gate identical, no allow/clear path"),
    ("policy_lint_test", "policy authoring validator: catches malformed control-function policies"),
    ("policy_schema_diff_test", "policy-vs-schema drift linter: too-tight (lockout) + too-loose (scan) drift"),
    ("ifc_test", "information-flow control: untrusted tool output can't drive a privileged sink (prompt-injection)"),
]
OPTIONAL = [
    ("verify_kdb_bridge", "bridges this repo's tools/gate.js (needs Node)"),
    ("formal_smt", "Z3 proofs over unbounded domains (needs z3-solver)"),
    ("q_conformance_test", "compiler safety bounds proven on REAL kdb+ (needs a q binary)"),
]


def _run(mod: str) -> tuple[bool, str]:
    r = subprocess.run([sys.executable, "-m", f"aegis.{mod}"],
                       capture_output=True, text=True)
    last = ""
    for line in (r.stdout or "").splitlines():
        if line.strip():
            last = line.strip()
    return r.returncode == 0, last


def run() -> int:
    print("=== Aegis acceptance suite ===\n")
    core_failed = []
    print("CORE:")
    for mod, desc in CORE:
        ok, last = _run(mod)
        if not ok:
            core_failed.append(mod)
        print(f"  {'PASS' if ok else 'FAIL'}  aegis.{mod:<18} {desc}")

    print("\nOPTIONAL (infra-dependent):")
    for mod, desc in OPTIONAL:
        ok, _ = _run(mod)
        print(f"  {'PASS' if ok else 'skip'}  aegis.{mod:<18} {desc}")

    n_core = len(CORE)
    n_ok = n_core - len(core_failed)
    print(f"\n{'ALL CORE PASS' if not core_failed else 'CORE FAILURES'} — {n_ok}/{n_core} core")
    if core_failed:
        print("  failed:", ", ".join(core_failed))
    return 1 if core_failed else 0


if __name__ == "__main__":
    sys.exit(run())
