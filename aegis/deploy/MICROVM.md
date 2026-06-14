# microVM substrate — hard isolation for adversarial / multi-tenant agents

Aegis's default Layer-1 confinement (Landlock + namespaces + rlimits, see
`CONFINEMENT.md`) is the frontier-standard sandbox for a **single-tenant,
trusted-operator** agent. It is, honestly, *weaker than a microVM against a
kernel-level attacker* — kernel vulnerabilities, side channels, and global
resource exhaustion are out of scope for any namespace/LSM sandbox
(arXiv:2605.26298). When the agent runs **adversarial or multi-tenant**
workloads (untrusted prompts that may attempt kernel escape, or several
tenants sharing a host), put a hardware/VM boundary under it.

This does **not** change Aegis: the policy, PDP, query/egress proxies, signed
audit, supervisor + kill switch are identical. Only the *substrate the agent
process runs on* changes — from a namespace sandbox to a microVM.

## Topology

```
                   ┌─ microVM (Firecracker / Kata) ───────────────┐
   agent code ───▶ │  guest kernel (own, not the host's)          │
                   │  Aegis confine_run.sh / landlock_confine.py  │  defence in depth
                   │  reaches out only to ↓                        │
                   └───────────────┬──────────────────────────────┘
                                   │ vsock / host-only net
        ┌──────────────────────────┴───────────────────────────┐
        │  host: aegis-pdp (signed policy, RO)  +  aegis-egress │  control plane
        └────────────────────────────────────────────────────────┘
```

The microVM gives the agent its **own guest kernel**, so a kernel exploit
inside the guest does not reach the host or other tenants. The Aegis PDP and
egress proxy stay on the host (or a separate control VM); the agent calls them
over a constrained channel (vsock or a host-only interface), and still gets
every tool call gated and every byte of egress DLP-inspected.

## Option A — Kata Containers (drop-in for the k8s path)

Kata runs each pod in a lightweight VM while keeping the Kubernetes/OCI
interface. The hardened `deploy/k8s.yaml` works unchanged except for the
runtime class:

```yaml
spec:
  runtimeClassName: kata-qemu      # or kata-clh (Cloud Hypervisor)
  # ... the existing securityContext / NetworkPolicy still apply inside the VM
```

Install the Kata runtime + a `RuntimeClass` named `kata-qemu` on the cluster;
no application change. The default-deny egress NetworkPolicy and the read-only
signed-policy mount continue to hold *inside* the guest.

## Option B — Firecracker (standalone / non-k8s)

Firecracker boots a minimal microVM in ~125 ms. Pattern:

1. Build a rootfs image containing python3 + the `aegis` package + the agent.
2. Boot a Firecracker VM with that rootfs, no network device except a
   host-only tap routed to `aegis-egress`, and a vsock to reach `aegis-pdp`.
3. Inside the guest, run the agent under `confine_run.sh` / `landlock_confine.py`
   as a second layer.
4. The host's PDP enforces policy on every tool call over vsock; the agent has
   no other route off the VM.

Frameworks that wrap this for agent code (evaluate per your stack): **E2B**,
**Modal**, **Daytona**, **microsandbox** — all Firecracker-based. Aegis sits
*inside* the guest (confinement) and *on the host* (PDP/egress); the microVM
framework provides the VM boundary.

## When to use which

| Workload | Substrate |
|---|---|
| Internal agent, trusted operators, single tenant | Landlock + namespaces (default) |
| Agent processing untrusted external input that could attempt escape | microVM |
| Multiple tenants / customers sharing a host | microVM (per-tenant VM) |
| Regulated, "assume breach of the agent" posture | microVM + everything else |

## What Aegis still owns regardless of substrate

The substrate only bounds blast radius. The *decisions* — what tools/queries
/egress are allowed, signed policy, tamper-evident audit, the supervisor's
circuit-breaker kill switch — are Aegis's and identical in every substrate.
Choosing a microVM is a deployment decision; it is not a different product.
