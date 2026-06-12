# Red-team evasion corpus

`python -m aegis.redteam_corpus` — the adversarial acceptance test. Runs every
bypass technique from `THREAT_MODEL.md` §4 against the live components and
classifies each as **caught now** or **deferred** to a downstream layer.

This is the artifact for a bank's security review: it states the catch-rate
*and the coverage boundary*, rather than claiming blanket protection.

## How to read it

- **caught** — the PDP (default-deny + detectors) or the query proxy stops or
  rewrites the action now. The host/DB never sees it unsafe.
- **defer:<layer>** — by design, the PDP/proxy *cannot* catch this from the
  request alone (e.g. danger hidden inside a script a granted interpreter runs,
  or a payload only visible on the wire). It is stopped by **L1 confinement**
  or the **egress proxy**. Documented boundary, not a silent gap.
- The suite **fails only on an unexpected miss** — a `caught` case that slipped
  (a real regression). Deferred cases that *become* caught are logged as bonus.

## Current result (23 cases)

| | count | notes |
|---|---:|---|
| caught by PDP/proxy now | 18 | incl. all obfuscation/laundering via *ungranted* binaries + egress-channel |
| deferred to confinement | 4 | RT-06 opaque interpreter exfil, RT-08 script-file, RT-09 TOCTOU, RT-10 symlink |
| deferred to egress proxy (at PDP) | 1 | RT-15 — its on-the-wire form RT-22 IS caught by the egress proxy |
| unexpected misses | 0 | — |

Defense-in-depth shown explicitly: RT-15 (a Bash `curl` to an allowlisted host)
is deferred by the PDP, but the same exfiltration on the wire (RT-22) is caught
by the egress proxy's payload DLP. Same attack, two layers.

## What the result demonstrates

1. **Default-deny earns its keep.** RT-01/02/03/14 (quoted binary name, `${IFS}`,
   `base64|sh`, DNS-exfil) defeat *denylists* but are caught because the binary
   allowlist enumerates goodness — anything not granted is blocked.
2. **Detectors catch visible signal** inside granted interpreters (RT-05 urllib
   exfil, RT-07 inline `system"rm -rf"`, RT-13 raw-IP exfil).
3. **The 5 deferred cases prove the layered design is required, not optional.**
   No request-time analysis can catch a base64-opaque payload a granted Python
   runs (RT-06) or a secret reached via a symlink (RT-10). Only confinement /
   the egress proxy can. This is *why* Aegis is a stack, not a regex.

## Maintenance

Every new detector or grant should add cases here. A new rule isn't "done"
until the corpus exercises it. When the egress proxy lands, RT-15 (and RT-06's
network path) move from `defer` to `caught` — the corpus will show it.
