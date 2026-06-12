"""CI gate: verify a real deployment manifest is hardened before it ships.

This is the bridge from `aegis.confinement` (which validates a normalized
profile) to the actual artifacts a bank deploys. It parses the K8s manifest
with PyYAML, normalizes the agent Deployment's Pod template via
`from_k8s_pod`, and runs every confinement control — failing closed (exit 1)
if any control is not satisfied.

Run it in CI on the manifest the bank will actually apply:

    python tools/verify_deployment.py aegis/deploy/k8s.yaml
    python tools/verify_deployment.py my-cluster/governed-agent.yaml --pod-label app=governed-agent

It also cross-checks the committed deployment-profile.json against the
manifest, so the two cannot silently drift.

Exit codes: 0 = hardened; 1 = a control failed / manifest unparseable;
2 = could not find the agent Pod in the manifest (usage error).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402

from aegis.confinement import check_profile, from_k8s_pod  # noqa: E402


def _pod_template_docs(docs: list[dict], label: str | None):
    """Yield Pod specs from Deployment/Pod docs, optionally filtered by a
    `key=value` label on the Pod template."""
    want = None
    if label and "=" in label:
        k, v = label.split("=", 1)
        want = (k, v)
    for d in docs:
        if not isinstance(d, dict):
            continue
        kind = d.get("kind")
        if kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"):
            tmpl = d.get("spec", {}).get("template", {})
            tmpl_meta = dict(tmpl.get("metadata", {}) or {})
            # Cluster-level facts (egress mode, PDP endpoint, audit sink, pids
            # limit) are documented as annotations on the workload, not the Pod
            # template. Carry them down so the validator sees them.
            dep_ann = (d.get("metadata", {}) or {}).get("annotations", {}) or {}
            tmpl_meta["annotations"] = {**dep_ann, **(tmpl_meta.get("annotations", {}) or {})}
            pod = {"metadata": tmpl_meta, "spec": tmpl.get("spec", {})}
        elif kind == "Pod":
            pod = d
        else:
            continue
        labels = (pod.get("metadata", {}) or {}).get("labels", {}) or {}
        if want and labels.get(want[0]) != want[1]:
            continue
        yield d.get("metadata", {}).get("name", kind), pod


def run(manifest: Path, label: str | None, profile_path: Path | None) -> int:
    try:
        docs = list(yaml.safe_load_all(manifest.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError) as e:
        print(f"FAIL — manifest unparseable: {e}")
        return 1

    pods = list(_pod_template_docs(docs, label))
    if not pods:
        print(f"could not find an agent Pod/Deployment in {manifest}"
              + (f" with label {label}" if label else ""))
        return 2

    print(f"=== deployment hardening gate: {manifest.name} ===\n")
    all_ok = True
    for name, pod in pods:
        profile = from_k8s_pod(pod)
        results = check_profile(profile)
        n_ok = sum(1 for _, ok, _ in results if ok)
        print(f"workload '{name}': {n_ok}/{len(results)} controls satisfied")
        for c, ok, detail in results:
            print(f"  {'PASS' if ok else 'FAIL'}  {c.id:<22} {detail}")
            if not ok:
                print(f"        closes: {c.closes}")
        all_ok = all_ok and (n_ok == len(results))
        print()

        if profile_path and profile_path.exists():
            committed = json.loads(profile_path.read_text(encoding="utf-8"))
            committed.pop("_comment", None)
            drift = [k for k in committed
                     if k in profile and committed[k] != profile[k]]
            if drift:
                print(f"  NOTE: manifest differs from {profile_path.name} on: {drift}")
                print("        (not a failure — but reconcile the source-of-truth profile)\n")

    print(f"{'PASS — manifest is hardened' if all_ok else 'FAIL — manifest is NOT hardened, do not deploy'}")
    return 0 if all_ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("manifest", type=Path, nargs="?",
                    default=Path(__file__).resolve().parent.parent / "aegis" / "deploy" / "k8s.yaml")
    ap.add_argument("--pod-label", default=None,
                    help="select the Pod by a template label, e.g. app=governed-agent")
    ap.add_argument("--profile", type=Path,
                    default=Path(__file__).resolve().parent.parent / "aegis" / "deploy" / "deployment-profile.json",
                    help="committed profile to cross-check against (drift detection)")
    args = ap.parse_args()
    return run(args.manifest, args.pod_label, args.profile)


if __name__ == "__main__":
    sys.exit(main())
