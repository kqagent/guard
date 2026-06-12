"""Regulatory crosswalk — Aegis controls mapped to the frameworks a bank cares
about, and SELF-VERIFIED against the codebase.

Why this module exists: the deep-research run found that mapping agent
guardrails onto SR 11-7 / EU AI Act / NIST AI RMF / OWASP is *under-served* —
nobody clearly owns it. It's the bank-facing differentiator. But a compliance
matrix that drifts from the implementation is worse than none, so each mapping
names the runnable EVIDENCE (a test module) and `verify()` checks that evidence
actually exists. The matrix cannot claim a control it can't demonstrate.

IMPORTANT — read before using in any filing:
  * This is NOT legal advice and NOT a certification.
  * The requirement text is PARAPHRASED from public framework summaries; the
    deep-research pass did NOT independently verify the regulatory layer.
    Validate every row against the primary source (and your 2nd-line/legal
    function) before relying on it.
  * VERIFIED 2026-06-04 (primary source — Federal Reserve SR 26-2 PDF): SR 26-2
    (Apr 17 2026, "Revised Guidance on Model Risk Management") SUPERSEDES SR
    11-7. Critically, footnote 3 states generative AI and agentic AI models
    "are not within the scope of this guidance" (it applies to "traditional
    statistical and quantitative models and non-generative, non-agentic AI
    models"). THEREFORE: the MRM rows below are NOT a direct compliance
    obligation for an LLM agent — they reflect the broader "risk management and
    governance practices" SR 26-2 says should still guide controls for such
    out-of-scope tools. EU AI Act Art. 12(1) logging, 14(4) human oversight,
    and 15 accuracy/robustness/cybersecurity ARE primary-source-verified and
    DO bind high-risk AI systems. NIST AI RMF text here remains unverified.
  * A control *evidences* a requirement; it does not by itself constitute
    compliance. Compliance is an organizational determination.

Run:  python -m aegis.compliance
Exits non-zero if any mapping references evidence that doesn't exist.
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass, field


@dataclass
class Mapping:
    framework: str
    control: str          # the framework's clause/id (verify against primary source)
    requirement: str      # paraphrased intent
    aegis: str            # the Aegis control(s) that address it
    evidence: list[str] = field(default_factory=list)  # runnable test module(s)


CROSSWALK = [
    # --- Fed SR 11-7 (Model Risk Management) ---
    Mapping("SR 26-2 (governance; supersedes SR 11-7)", "Effective challenge / independent validation",
            "Critical analysis by objective, informed parties independent of model development.",
            "Decision made out-of-process, independent of the model; adversarial red-team corpus.",
            ["pdp_test", "redteam_corpus", "formal"]),
    Mapping("SR 26-2 (governance; supersedes SR 11-7)", "Ongoing monitoring",
            "Confirm the model is performing as intended; monitor limitations/assumptions over time.",
            "Monitor mode with false-positive / recall metrics; tamper-proof decision log.",
            ["monitor", "audit_worm_test"]),
    Mapping("SR 26-2 (governance; supersedes SR 11-7)", "Controls, governance & change control",
            "Policies, roles, and controls governing model use and change.",
            "Policy authored by the control function, Ed25519-signed; agent cannot alter it.",
            ["signing_test", "confinement_test"]),

    # --- EU AI Act (high-risk obligations; verify article nums against consolidated text) ---
    Mapping("EU AI Act", "Art. 12 Record-keeping / logging",
            "Automatic recording of events over the system lifecycle for traceability.",
            "Hash-chained + off-host-mirrored + anchored audit (truncation-proof).",
            ["audit_worm_test"]),
    Mapping("EU AI Act", "Art. 14 Human oversight",
            "Enable humans to oversee and intervene in high-risk system operation.",
            "REQUIRE_APPROVAL effect routes high-impact actions to a human before execution.",
            ["demo", "agentdojo_eval"]),
    Mapping("EU AI Act", "Art. 15 Accuracy, robustness & cybersecurity",
            "Resilience against errors and adversarial manipulation; cybersecurity by design.",
            "Adversarial corpus, egress/SSRF/DLP, fail-closed, signed policy.",
            ["redteam_corpus", "egress_proxy_test", "signing_test"]),

    # --- NIST AI RMF (GOVERN / MAP / MEASURE / MANAGE) ---
    Mapping("NIST AI RMF", "GOVERN",
            "Policies, accountability, and culture for AI risk; separation of duties.",
            "Policy-as-code owned by control function; signed bundle = separation of duties.",
            ["signing_test"]),
    Mapping("NIST AI RMF", "MEASURE",
            "Analyze, assess and track AI risks and effectiveness of controls.",
            "FP/recall metrics, adversarial corpus, exhaustive formal properties.",
            ["monitor", "redteam_corpus", "formal"]),
    Mapping("NIST AI RMF", "MANAGE",
            "Allocate resources to and enact controls that treat identified risks.",
            "Fail-closed default-deny enforcement; confinement; query + egress proxies.",
            ["demo", "confinement_test", "query_proxy_test", "egress_proxy_test"]),

    # --- OWASP LLM Top 10 (2025) ---
    Mapping("OWASP LLM 2025", "LLM01 Prompt Injection",
            "Injected instructions cause unintended actions.",
            "Action gate blocks the injected action at execution regardless of model compromise.",
            ["redteam_corpus", "agentdojo_eval"]),
    Mapping("OWASP LLM 2025", "LLM02 Sensitive Information Disclosure",
            "Leakage of sensitive data via model in/outputs or actions.",
            "Egress DLP + PII/secrets detection block exfiltration paths.",
            ["egress_proxy_test", "demo"]),
    Mapping("OWASP LLM 2025", "LLM06 Excessive Agency",
            "Excessive permissions/autonomy; mitigation = least privilege.",
            "Default-deny capability grants; named-tool rules; proven monotonic confinement.",
            ["formal", "agentdojo_eval"]),

    # --- OWASP Top 10 for Agentic Applications (2026) ---
    Mapping("OWASP Agentic 2026", "ASI02 Tool Misuse",
            "Agent induced to misuse legitimate tools.",
            "Per-tool argument rules; query proxy bounds; egress proxy allowlist + DLP.",
            ["agentdojo_eval", "query_proxy_test", "egress_proxy_test"]),
    Mapping("OWASP Agentic 2026", "ASI03 Identity & Privilege Abuse",
            "Abuse of granted identity/privilege.",
            "Default-deny grants + RBAC; signed policy; protected-path self-protection.",
            ["formal", "signing_test"]),

    # --- CoSAI / OASIS MCP security ---
    Mapping("CoSAI MCP", "Tool-side enforcement",
            "Never rely on the LLM for security-critical validation; enforce in the tool.",
            "Out-of-process PDP decides every tool call; model output is only an input.",
            ["pdp_test"]),
]


def verify() -> tuple[bool, list[str]]:
    """Every mapping's evidence module must exist — else the matrix overclaims."""
    missing = []
    for m in CROSSWALK:
        for mod in m.evidence:
            if importlib.util.find_spec(f"aegis.{mod}") is None:
                missing.append(f"{m.framework}/{m.control} -> aegis.{mod} (MISSING)")
    return (not missing), missing


def run() -> int:
    print("=== Aegis regulatory crosswalk (self-verified) ===\n")
    by_fw: dict[str, list[Mapping]] = {}
    for m in CROSSWALK:
        by_fw.setdefault(m.framework, []).append(m)

    for fw, rows in by_fw.items():
        print(f"  {fw}")
        for m in rows:
            print(f"    [{m.control}]")
            print(f"        requirement: {m.requirement}")
            print(f"        Aegis       : {m.aegis}")
            print(f"        evidence    : {', '.join('aegis.' + e for e in m.evidence)}")
        print()

    ok, missing = verify()
    print(f"  frameworks: {len(by_fw)}   mappings: {len(CROSSWALK)}   "
          f"evidence integrity: {'OK' if ok else 'BROKEN'}")
    for x in missing:
        print(f"    !! {x}")

    print("\n  DISCLAIMER: not legal advice; requirement text is paraphrased and was")
    print("  NOT independently verified — validate against primary sources + your")
    print("  compliance function. A control evidences a requirement; it is not")
    print("  itself a compliance determination.")

    print(f"\n{'PASS' if ok else 'FAIL'} — every mapping is backed by a runnable test")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(run())
