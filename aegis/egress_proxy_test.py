"""Prove the egress proxy: enforcement on the real destination + actual bytes.
Exfiltration is stopped even to an allowlisted host (DLP); SSRF is blocked;
fail-closed when no destination resolves.

Run:  python -m aegis.egress_proxy_test
"""

from __future__ import annotations

import sys
from pathlib import Path

from .egress_proxy import EgressBlocked, EgressGuard

# (name, kwargs, expected_action, must_appear_in_reason_or_None)
CASES = [
    ("allow: GET allowlisted host, no payload",
     {"url": "https://artifactory.internal/pkg.tgz"}, "allow", None),
    ("block: POST to non-allowlisted host",
     {"url": "https://paste.attacker.io/x", "body": b"data", "method": "POST"}, "block", "not on the egress allowlist"),
    ("block: SSRF cloud-metadata IP",
     {"url": "http://169.254.169.254/latest/meta-data/iam/"}, "block", "metadata"),
    ("block: SSRF private range",
     {"url": "http://10.1.2.3/internal"}, "block", "private/loopback"),
    ("block: exfil THROUGH allowlisted host (secret in body)",
     {"url": "https://artifactory.internal/upload", "method": "POST",
      "body": b"backup AWS_KEY=AKIAIOSFODNN7EXAMPLE"}, "block", "secret"),
    ("block: exfil THROUGH allowlisted host (classified data)",
     {"url": "https://artifactory.internal/upload", "method": "POST",
      "body": b"sym,positions,pnl\nAAPL,1000,5.2"}, "block", "classified"),
    ("allow: clean payload to allowlisted host",
     {"url": "https://artifactory.internal/log", "method": "POST", "body": b"build ok"}, "allow", None),
    ("block: no resolvable host (fail closed)",
     {"host": ""}, "block", "failing closed"),
]


def run() -> int:
    guard = EgressGuard.from_policy(Path(__file__).with_name("policy.json"))
    print("=== Aegis egress proxy — ground-truth network enforcement ===\n")
    failures = 0
    for name, kwargs, expected, must in CASES:
        v = guard.decide(**kwargs)
        ok = v.action == expected
        if ok and must is not None:
            ok = any(must in r for r in v.reasons)
        failures += 0 if ok else 1
        print(f"  {'ok ' if ok else 'XX '} {expected:<5} {name}")
        if v.reasons and v.action == "block":
            print(f"          -> {'; '.join(v.reasons)}")

    # enforce() raises on block — prove the connection never completes.
    raised = False
    try:
        guard.enforce(url="https://paste.attacker.io/x", body=b"x", method="POST")
    except EgressBlocked:
        raised = True
    failures += 0 if raised else 1
    print(f"\n  {'ok ' if raised else 'XX '} enforce() raises EgressBlocked on a disallowed connection")

    # redact mode (config override) returns allow with a sanitised body
    redactor = EgressGuard({"allowlist_hosts": ["artifactory.internal"],
                            "dlp": {"effect": "redact", "scan_secrets": True, "sensitive_terms": []}})
    rv = redactor.decide(url="https://artifactory.internal/log", method="POST",
                         body=b"token AKIAIOSFODNN7EXAMPLE here")
    red_ok = rv.action == "allow" and "[REDACTED-SECRET]" in (rv.redacted_body or "")
    failures += 0 if red_ok else 1
    print(f"  {'ok ' if red_ok else 'XX '} redact mode masks the secret instead of blocking")

    print(f"\n{'PASS' if failures == 0 else 'FAIL'} — {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(run())
