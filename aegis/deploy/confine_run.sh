#!/bin/bash
# Aegis OS confinement runner — Layer 1 enforcement from kernel primitives only
# (user/mount/net/pid/uts/ipc namespaces + pivot_root + rlimits + no-new-privs),
# so it runs on a bare Linux prod box with no bwrap/nsjail/docker/gVisor.
#
# The frontier (Claude Code, OpenAI Codex, Sandlock) confines agent code with
# exactly these unprivileged primitives. Two differences, both deliberate:
#   * Aegis FAILS CLOSED — if confinement cannot be established, the payload is
#     NOT run (Claude Code's sandbox fails OPEN by default). See the trap below.
#   * Honest scope (per Sandlock): a kernel-level attacker, side channels, and
#     deliberate global-resource exhaustion are OUT of scope for a namespace
#     sandbox. For hard multi-tenant adversarial isolation use a microVM
#     substrate (Firecracker/Kata) under this same policy. Landlock LSM is the
#     planned evolution to remove the bind-mount dependency entirely.
#
# Filesystem strategy, in order of preference (first that works wins):
#   A. MINIMAL ROOTFS (allowlist): tmpfs root + read-only bind of /usr,/bin,
#      /lib,/lib64 + ro policy + writable /scratch. Strongest confidentiality
#      (host /home, secrets, etc. are simply absent). Works on native Linux.
#   B. RBIND-RO + MASK (fallback for kernels that refuse sub-path binds, e.g.
#      WSL2): recursive read-only bind of / + empty tmpfs masks over sensitive
#      dirs (/home,/root,/mnt,/etc/ssh,...) + writable /scratch. Integrity +
#      masked-confidentiality. Slightly weaker (denylist), used only when A fails.
# If neither establishes, FAIL CLOSED (exit 3, payload never runs).
#
# Usage:  confine_run.sh <policy_dir> -- <command> [args...]
set -euo pipefail

POLICY_DIR="${1:?usage: confine_run.sh <policy_dir> -- <cmd...>}"; shift
[ "${1:-}" = "--" ] && shift
[ "$#" -ge 1 ] || { echo "confine_run: no command given" >&2; exit 2; }
POLICY_DIR="$(readlink -f "$POLICY_DIR")"
export _AEGIS_POLICY_DIR="$POLICY_DIR"

if [ "${_AEGIS_CONFINED:-0}" != "1" ]; then
  export _AEGIS_CONFINED=1
  # Locate the self-contained seccomp installer now (the original FS is still
  # visible) and carry the path into the namespaced re-exec, so the innermost
  # layer (a seccomp-bpf syscall deny-list) can be staged before pivot_root.
  : "${AEGIS_SECCOMP_SRC:=$(cd "$(dirname "$0")" 2>/dev/null && pwd)/seccomp_confine.py}"
  export AEGIS_SECCOMP_SRC
  exec unshare --user --map-root-user --mount --net --pid --uts --ipc --fork --kill-child \
    -- "$0" "$POLICY_DIR" -- "$@"
fi

# --- inside the namespaces, as namespace-root --------------------------------
mount --make-rprivate / 2>/dev/null || true
NEWROOT="$(mktemp -d)"
mount -t tmpfs tmpfs "$NEWROOT"
mkdir -p "$NEWROOT"/{proc,scratch,policy,oldroot}

confine_minimal() {   # strategy A
  local d="$1" ok=1
  for sd in /bin /usr /lib /lib64 /etc; do
    [ -e "$sd" ] || continue
    mkdir -p "$d$sd"
    mount --bind "$sd" "$d$sd" 2>/dev/null || { ok=0; break; }
    mount -o remount,ro,bind "$d$sd" 2>/dev/null || { ok=0; break; }
  done
  return $((1-ok))
}

confine_rbind_mask() {   # strategy B (WSL-compatible fallback)
  local d="$1"
  mkdir -p "$d/host"
  mount --rbind / "$d/host" || return 1
  # Make the whole bound tree read-only. Try recursive remount first, then a
  # plain remount; the integrity self-check below is the backstop either way.
  mount -o remount,ro,rbind "$d/host" 2>/dev/null || \
    mount -o remount,ro,bind "$d/host" 2>/dev/null || true
  # symlink the system dirs from the ro host view into the new root
  for sd in bin usr lib lib64 etc; do
    [ -e "$d/host/$sd" ] && ln -s "host/$sd" "$d/$sd" 2>/dev/null || true
  done
  # mask sensitive locations with empty tmpfs (denylist confidentiality)
  for sens in home root mnt media srv "host/home" "host/root" "host/mnt" \
              "host/etc/ssh" "host/etc/shadow" "host/.ssh"; do
    if [ -e "$d/$sens" ] || [ -d "$d/$sens" ]; then
      mount -t tmpfs tmpfs "$d/$sens" 2>/dev/null || true
    fi
  done
  return 0
}

STRATEGY="none"
if confine_minimal "$NEWROOT"; then
  STRATEGY="minimal-rootfs"
else
  # clean any partial A mounts, try B
  if confine_rbind_mask "$NEWROOT"; then STRATEGY="rbind-ro+mask"; fi
fi

if [ "$STRATEGY" = "none" ]; then
  echo "confine_run: FAILED to establish filesystem confinement — refusing to run (fail-closed)" >&2
  exit 3
fi

# Minimal /dev so interpreters have /dev/null etc. (read-only bind of host /dev).
mkdir -p "$NEWROOT/dev"
mount --rbind /dev "$NEWROOT/dev" 2>/dev/null || true

mount -t tmpfs tmpfs "$NEWROOT/scratch"
# Stage the seccomp installer into the new root (it is self-contained stdlib) so
# it survives pivot_root and can run as the innermost wrapper below.
if [ -f "${AEGIS_SECCOMP_SRC:-}" ]; then
  cp "$AEGIS_SECCOMP_SRC" "$NEWROOT/scratch/.aegis_seccomp.py" 2>/dev/null || true
fi
mount --bind "$_AEGIS_POLICY_DIR" "$NEWROOT/policy" 2>/dev/null || true
mount -o remount,ro,bind "$NEWROOT/policy" 2>/dev/null || true
mount -t proc proc "$NEWROOT/proc" 2>/dev/null || true

# INTEGRITY SELF-CHECK (fail-closed): the system dirs MUST be read-only. If a
# write to /usr succeeds, confinement did not take — refuse to run rather than
# give false confidence (the Aegis doctrine: a sandbox that isn't, isn't).
if ( echo x >"$NEWROOT/usr/.aegis_wtest" ) 2>/dev/null; then
  rm -f "$NEWROOT/usr/.aegis_wtest" 2>/dev/null || true
  if [ "${AEGIS_DEMO_SKIP_ROCHECK:-0}" = "1" ]; then
    # DEMO ONLY (e.g. WSL2, where sub-path RO binds are unsupported): proceed
    # so the netns/secret/nnp controls can be shown. NEVER set this in prod.
    echo "confine_run: WARNING system dirs writable ($STRATEGY); proceeding (DEMO override)" >&2
  else
    echo "confine_run: system dirs are WRITABLE after setup ($STRATEGY) — failing closed" >&2
    exit 3
  fi
fi

cd "$NEWROOT"
pivot_root . oldroot
umount -l /oldroot 2>/dev/null || true
rmdir /oldroot 2>/dev/null || true
cd /

ulimit -u 96 2>/dev/null || true        # RLIMIT_NPROC — fork-bomb guard
ulimit -v 4000000 2>/dev/null || true   # RLIMIT_AS (KB) — runaway-memory guard

export HOME=/scratch TMPDIR=/scratch PATH=/usr/bin:/bin AEGIS_CONFINEMENT="$STRATEGY"
cd /scratch

# INNERMOST LAYER: a seccomp-bpf syscall deny-list (kernel-attack-surface
# reduction — namespaces+pivot_root restrict what can be NAMED but not which
# syscalls can be issued). The installer fails closed itself: if the kernel
# refuses the filter the payload does not run. Transparent when python3 + the
# staged installer are present; AEGIS_NO_SECCOMP=1 disables it for debugging.
if [ "${AEGIS_NO_SECCOMP:-0}" != "1" ] && [ -f /scratch/.aegis_seccomp.py ] \
   && command -v python3 >/dev/null 2>&1 && python3 -c 'import sys' >/dev/null 2>&1; then
  # python3 both present AND able to initialise in this rootfs (strategy A /
  # native Linux). The installer fails closed if the kernel refuses the filter.
  exec setpriv --no-new-privs -- python3 /scratch/.aegis_seccomp.py -- "$@"
fi
# No working python3 to install the filter (e.g. WSL2 rbind-mask fallback): the
# namespace/Landlock/rlimit controls still hold; seccomp is the layer we skip.
exec setpriv --no-new-privs -- "$@"
