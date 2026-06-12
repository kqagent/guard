"""Confinement validator — Layer 1, verified deterministically.

Confinement is enforced by the OS/container runtime, not by Python. But "did
ops actually deploy it locked down?" must not be left to trust — so this module
checks a deployment descriptor against the required hardening controls and
fails closed: any control that is missing, false, or unparseable is treated as
NOT satisfied. Same philosophy as the rest of Aegis (deterministic, testable,
fail-closed). A bank runs this in CI against their real manifest before deploy.

Input is a normalized deployment profile (see deploy/deployment-profile.json).
`from_k8s_pod()` best-effort-normalizes a Kubernetes Pod spec into that profile.

Each control names the red-team case(s) / threat it closes, so the coverage map
ties directly back to THREAT_MODEL.md and the corpus.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

_ALLOWED_WRITABLE = {"/scratch", "/tmp", "/var/aegis/scratch"}
# Paths that must be present AND read-only (the guardrails themselves).
_PROTECTED_RO = ["policy.json", "policy.json.sig", "pubkey"]


@dataclass
class Control:
    id: str
    desc: str
    closes: str            # red-team ids / threat-model class this control closes
    check: Callable[[dict], tuple[bool, str]]


def _is_true(p, k):
    return p.get(k) is True


def _c_ro_rootfs(p):
    return (_is_true(p, "read_only_root_fs"),
            "read-only root filesystem prevents writing binaries/laundered scripts")


def _c_nonroot(p):
    ok = _is_true(p, "run_as_non_root") and p.get("run_as_user") not in (None, 0)
    return ok, f"run as non-root (uid={p.get('run_as_user')})"


def _c_no_new_priv(p):
    return _is_true(p, "no_new_privileges"), "privilege escalation disabled"


def _c_drop_caps(p):
    drop = {c.upper() for c in p.get("drop_capabilities", [])}
    add = [c for c in p.get("add_capabilities", []) if c.upper() not in ("NET_BIND_SERVICE",)]
    return ("ALL" in drop and not add), f"drop=ALL add={p.get('add_capabilities', [])}"


def _c_seccomp(p):
    s = p.get("seccomp")
    ok = s == "RuntimeDefault" or (isinstance(s, str) and s.startswith("localhost/"))
    return ok, f"seccomp profile = {s}"


def _c_no_host_ns(p):
    ok = p.get("host_network") is False and p.get("host_pid") is False and p.get("host_ipc") is False
    return ok, "no host network/pid/ipc namespaces"


def _c_egress_proxy(p):
    ok = p.get("network_egress") == "deny-all-except-proxy" and bool(p.get("egress_proxy"))
    return ok, f"egress={p.get('network_egress')} via {p.get('egress_proxy')}"


def _c_ro_policy(p):
    mounts = [m.replace("\\", "/") for m in p.get("read_only_mounts", [])]
    missing = [name for name in _PROTECTED_RO if not any(name in m for m in mounts)]
    return (not missing), ("policy/sig/pubkey read-only" if not missing
                           else f"MISSING read-only mounts for: {', '.join(missing)}")


def _c_min_writable(p):
    bad = [m for m in p.get("writable_mounts", []) if m not in _ALLOWED_WRITABLE]
    return (not bad), ("writable mounts limited to scratch" if not bad
                       else f"unexpected writable mounts: {bad}")


def _c_resource_limits(p):
    rl = p.get("resource_limits", {}) or {}
    ok = all(rl.get(k) for k in ("cpu", "memory", "pids"))
    return ok, f"limits set: {sorted(k for k in rl if rl.get(k))}"


def _c_remote_audit(p):
    return (p.get("audit_sink") == "remote"), f"audit_sink = {p.get('audit_sink')}"


def _c_out_of_proc_pdp(p):
    return bool(p.get("pdp_endpoint")), f"PDP endpoint = {p.get('pdp_endpoint')}"


CONTROLS = [
    Control("CONF-RO-ROOTFS", "read-only root filesystem", "RT-08 (script write), laundering", _c_ro_rootfs),
    Control("CONF-NONROOT", "run as non-root user", "privilege escalation", _c_nonroot),
    Control("CONF-NO-NEW-PRIV", "no-new-privileges", "privilege escalation", _c_no_new_priv),
    Control("CONF-DROP-CAPS", "drop all Linux capabilities", "host escape", _c_drop_caps),
    Control("CONF-SECCOMP", "seccomp syscall filter", "kernel attack surface", _c_seccomp),
    Control("CONF-NO-HOST-NS", "no host namespaces", "isolation", _c_no_host_ns),
    Control("CONF-EGRESS-PROXY", "egress only via the egress proxy", "RT-06, RT-15/RT-22 (exfil)", _c_egress_proxy),
    Control("CONF-RO-POLICY", "policy/signature/pubkey mounted read-only", "RT-12 (edit guardrails), integrity", _c_ro_policy),
    Control("CONF-MIN-WRITABLE", "writable mounts limited to scratch", "RT-09/RT-10 (no asset to reach)", _c_min_writable),
    Control("CONF-RESOURCE-LIMITS", "cpu/memory/pids limits", "runaway / fork-bomb", _c_resource_limits),
    Control("CONF-REMOTE-AUDIT", "audit streamed off-host", "audit destruction (F)", _c_remote_audit),
    Control("CONF-OUT-OF-PROC-PDP", "PDP runs out-of-process", "agent tamper of decision logic", _c_out_of_proc_pdp),
]


def check_profile(profile: dict) -> list[tuple[Control, bool, str]]:
    """Run all controls. Fail-closed: a control whose predicate raises is a
    failure, not an exception."""
    results = []
    for c in CONTROLS:
        try:
            ok, detail = c.check(profile or {})
        except Exception as e:  # malformed profile -> control not satisfied
            ok, detail = False, f"check errored ({type(e).__name__}) — treated as NOT satisfied"
        results.append((c, ok, detail))
    return results


def is_hardened(profile: dict) -> bool:
    return all(ok for _, ok, _ in check_profile(profile))


def from_k8s_pod(pod: dict) -> dict:
    """Best-effort normalize a Kubernetes Pod spec dict into a profile.
    Network egress and audit/PDP wiring are cluster-level (NetworkPolicy,
    sidecars), so they're read from pod annotations the deployer sets."""
    spec = pod.get("spec", {})
    psc = spec.get("securityContext", {}) or {}
    containers = spec.get("containers", [{}])
    c0 = containers[0] if containers else {}
    csc = c0.get("securityContext", {}) or {}
    ann = (pod.get("metadata", {}) or {}).get("annotations", {}) or {}

    caps = (csc.get("capabilities", {}) or {})
    mounts = c0.get("volumeMounts", []) or []
    limits = (c0.get("resources", {}) or {}).get("limits", {}) or {}

    def _g(key, *dicts, default=None):
        for d in dicts:
            if key in d:
                return d[key]
        return default

    return {
        "runtime": "container",
        "read_only_root_fs": csc.get("readOnlyRootFilesystem", False),
        "run_as_non_root": _g("runAsNonRoot", csc, psc, default=False),
        "run_as_user": _g("runAsUser", csc, psc),
        "no_new_privileges": (csc.get("allowPrivilegeEscalation") is False),
        "drop_capabilities": caps.get("drop", []),
        "add_capabilities": caps.get("add", []),
        "seccomp": (csc.get("seccompProfile", {}) or psc.get("seccompProfile", {}) or {}).get("type"),
        "host_network": spec.get("hostNetwork", False),
        "host_pid": spec.get("hostPID", False),
        "host_ipc": spec.get("hostIPC", False),
        "network_egress": ann.get("aegis.bank/egress", "open"),
        "egress_proxy": ann.get("aegis.bank/egress-proxy"),
        "read_only_mounts": [m.get("mountPath", "") for m in mounts if m.get("readOnly")],
        "writable_mounts": [m.get("mountPath", "") for m in mounts if not m.get("readOnly")],
        "resource_limits": {
            "cpu": limits.get("cpu"), "memory": limits.get("memory"),
            "pids": ann.get("aegis.bank/pids-limit"),
        } if limits else {},
        "audit_sink": ann.get("aegis.bank/audit-sink", "local"),
        "pdp_endpoint": ann.get("aegis.bank/pdp-endpoint"),
    }
