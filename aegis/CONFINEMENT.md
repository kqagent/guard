# Confinement — Layer 1, and how it's verified

Confinement is the load-bearing control: it makes whole attack classes
*impossible* rather than *detected*. It's enforced by the container runtime,
not by Aegis code — so the risk is silent misconfiguration. Aegis closes that
with a **deterministic validator** (`aegis/confinement.py`): feed it your
deployment descriptor, it checks every required control and **fails closed** on
anything missing. Run it in CI before deploy.

```
python -m aegis.confinement_test          # validates the reference profile + a weak one
```

## The controls and what each closes

| Control | Requirement | Closes |
|---|---|---|
| `CONF-RO-ROOTFS` | read-only root filesystem | RT-08 (can't write a laundered script), write-surface |
| `CONF-NONROOT` | run as non-root uid | privilege escalation |
| `CONF-NO-NEW-PRIV` | `allowPrivilegeEscalation: false` | privilege escalation |
| `CONF-DROP-CAPS` | drop ALL Linux capabilities | host escape |
| `CONF-SECCOMP` | seccomp `RuntimeDefault` or custom | kernel attack surface |
| `CONF-NO-HOST-NS` | no host network/pid/ipc | isolation |
| `CONF-EGRESS-PROXY` | egress **deny-all-except-proxy** | **RT-06, RT-15/RT-22** — no direct net, exfil must pass the egress proxy's DLP |
| `CONF-RO-POLICY` | policy.json + .sig + pubkey mounted **read-only** | **RT-12** — the agent can't write its own guardrails; completes the signing story at the OS layer |
| `CONF-MIN-WRITABLE` | only `/scratch` writable | **RT-09/RT-10** — the secret/asset isn't even present to reach |
| `CONF-RESOURCE-LIMITS` | cpu/memory/pids limits | runaway / fork-bomb |
| `CONF-REMOTE-AUDIT` | audit streamed off-host | audit destruction (threat F) |
| `CONF-OUT-OF-PROC-PDP` | PDP endpoint set (sidecar) | agent tampering with decision logic |

## How this closes the red-team "deferred" cases

The corpus deferred RT-06/08/09/10 because the PDP cannot catch them from the
request alone. Confinement closes them by construction — and the validator
proves the closing controls are actually configured:

- **RT-06** (opaque python exfil) → `CONF-EGRESS-PROXY`: no direct network; the
  exfil call can only leave via the egress proxy, which DLP-inspects it.
- **RT-08** (q runs a script) → `CONF-RO-ROOTFS` + no creds + no net: arbitrary
  code runs, but with ~zero blast radius — nothing to read, nowhere to send.
- **RT-09/RT-10** (TOCTOU / symlink to a secret) → `CONF-MIN-WRITABLE` +
  minimal mounts: the secret isn't mounted into the sandbox, so there's nothing
  to dereference.

So: **PDP defers → confinement closes → validator proves the config**. Defense
in depth, end to end, checkable.

## Deploy artifacts (in `deploy/`)

- `deployment-profile.json` — the normalized profile (source of truth the
  validator checks).
- `k8s.yaml` — hardened Deployment + default-deny egress NetworkPolicy.
- `Dockerfile` — non-root, read-only-friendly image + a reference hardened
  `docker run` line.

## The per-surface honesty (again)

This profile is for **operational agents in containers** — the watertight
surface. On **developer laptops** you cannot apply most of these controls; that
surface gets default-deny + detectors + audit (strong defense-in-depth) but not
L1 confinement. Tell the bank which surface gets which guarantee.
