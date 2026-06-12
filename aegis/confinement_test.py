"""Prove the confinement validator: a hardened deployment passes; an
under-hardened one fails with the exact missing controls (fail-closed). Also
proves the reference k8s Pod normalizes to a passing profile.

Run:  python -m aegis.confinement_test
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .confinement import check_profile, from_k8s_pod, is_hardened

# A deliberately weak deployment — what NOT to ship.
WEAK = {
    "read_only_root_fs": False,
    "run_as_non_root": False,
    "run_as_user": 0,
    "no_new_privileges": False,
    "drop_capabilities": [],
    "seccomp": None,
    "host_network": True,
    "host_pid": True,
    "host_ipc": True,
    "network_egress": "open",
    "read_only_mounts": [],
    "writable_mounts": ["/", "/etc/aegis"],
    "resource_limits": {},
    "audit_sink": "local",
    "pdp_endpoint": None,
}

# The reference k8s Pod (parsed form) — should normalize to a passing profile.
REF_POD = {
    "metadata": {"annotations": {
        "aegis.bank/egress": "deny-all-except-proxy",
        "aegis.bank/egress-proxy": "aegis-egress:8443",
        "aegis.bank/pdp-endpoint": "http://aegis-pdp:8787",
        "aegis.bank/audit-sink": "remote",
        "aegis.bank/pids-limit": "128",
    }},
    "spec": {
        "hostNetwork": False, "hostPID": False, "hostIPC": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{
            "securityContext": {
                "readOnlyRootFilesystem": True, "runAsNonRoot": True, "runAsUser": 65532,
                "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "resources": {"limits": {"cpu": "1", "memory": "512Mi"}},
            "volumeMounts": [
                {"mountPath": "/etc/aegis/policy.json", "readOnly": True},
                {"mountPath": "/etc/aegis/policy.json.sig", "readOnly": True},
                {"mountPath": "/etc/aegis/pubkey.hex", "readOnly": True},
                {"mountPath": "/scratch", "readOnly": False},
            ],
        }],
    },
}


def _report(title: str, profile: dict):
    print(f"  {title}")
    for c, ok, detail in check_profile(profile):
        print(f"    {'ok ' if ok else 'XX '} {c.id:<22} {detail}  [closes: {c.closes}]")


def run() -> int:
    failures = 0
    print("=== Aegis confinement validator ===\n")

    # 1) the reference profile must pass
    ref_profile = json.loads(
        (Path(__file__).parent / "deploy" / "deployment-profile.json").read_text(encoding="utf-8"))
    ok1 = is_hardened(ref_profile)
    failures += 0 if ok1 else 1
    print(f"  [{'ok ' if ok1 else 'XX '}] reference deployment-profile.json is HARDENED")

    # 2) the reference k8s Pod normalizes to a passing profile
    norm = from_k8s_pod(REF_POD)
    ok2 = is_hardened(norm)
    failures += 0 if ok2 else 1
    print(f"  [{'ok ' if ok2 else 'XX '}] reference k8s Pod normalizes to a HARDENED profile")

    # 3) a weak deployment must FAIL, and must NOT be reported as hardened
    ok3 = not is_hardened(WEAK)
    failures += 0 if ok3 else 1
    n_fail = sum(1 for _, ok, _ in check_profile(WEAK) if not ok)
    print(f"  [{'ok ' if ok3 else 'XX '}] weak deployment correctly REJECTED ({n_fail} controls unmet)\n")

    _report("weak deployment control-by-control:", WEAK)

    print(f"\n{'PASS' if failures == 0 else 'FAIL'} — {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(run())
