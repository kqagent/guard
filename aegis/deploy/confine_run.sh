#!/bin/bash
# Aegis OS confinement runner — Layer 1 enforcement, using ONLY kernel
# primitives (user/mount/net/pid/uts/ipc namespaces + pivot_root + rlimits),
# so it runs on a bare Linux prod box with no bwrap/nsjail/docker installed.
#
# It puts an agent command inside a sandbox where the OS — not Python, not a
# regex — makes escape impossible:
#   * pivot_root into a minimal rootfs: only RO system libs/tools, a RO policy
#     mount, and a writable tmpfs /scratch are visible. /home, host /etc
#     secrets, the rest of the filesystem DO NOT EXIST in this view.
#   * a fresh network namespace with no configured interface: egress is
#     physically impossible (no route to anywhere).
#   * --map-root-user gives root INSIDE the namespace only; it maps to the
#     unprivileged real uid outside, so "root" here owns nothing on the host.
#   * RLIMIT_NPROC / RLIMIT_AS cap processes and memory (fork-bomb / OOM guard).
#   * --no-new-privs blocks privilege escalation (setuid/file-caps gain nothing).
#
# Usage:  confine_run.sh <policy_dir> -- <command> [args...]
#         echo '<script>' | confine_run.sh <policy_dir> -- <interpreter>
#
# Exit code is the payload's. Designed to be invoked by the PDP/agent harness
# as the execution substrate for any tool call that runs code on the box.
set -euo pipefail

POLICY_DIR="${1:?usage: confine_run.sh <policy_dir> -- <cmd...>}"; shift
[ "${1:-}" = "--" ] && shift
[ "$#" -ge 1 ] || { echo "confine_run: no command given" >&2; exit 2; }
POLICY_DIR="$(readlink -f "$POLICY_DIR")"

export _AEGIS_POLICY_DIR="$POLICY_DIR"

# Re-exec ourselves inside fresh namespaces, mapped-root, with a child reaper.
if [ "${_AEGIS_CONFINED:-0}" != "1" ]; then
  export _AEGIS_CONFINED=1
  exec unshare --user --map-root-user --mount --net --pid --uts --ipc --fork --kill-child \
    -- "$0" "$POLICY_DIR" -- "$@"
fi

# --- now inside the namespaces, as (namespace-)root -------------------------
# Make mount propagation private so our changes don't leak to the host.
mount --make-rprivate / 2>/dev/null || true

NEWROOT="$(mktemp -d)"
mount -t tmpfs tmpfs "$NEWROOT"
mkdir -p "$NEWROOT"/{bin,usr,lib,lib64,etc,proc,scratch,policy,oldroot}

# RO system dirs the agent legitimately needs to run interpreters/tools.
for d in /bin /usr /lib /lib64; do
  if [ -e "$d" ]; then
    mount --bind "$d" "$NEWROOT$d"
    mount -o remount,ro,bind "$NEWROOT$d"
  fi
done

# The ONLY writable location.
mount -t tmpfs tmpfs "$NEWROOT/scratch"

# Guardrails mounted READ-ONLY — present but unwritable to the agent.
mount --bind "$_AEGIS_POLICY_DIR" "$NEWROOT/policy"
mount -o remount,ro,bind "$NEWROOT/policy"

# Minimal /etc: just resolver/hosts shells expect; NO host secrets copied.
printf 'aegis-confined\n' > "$NEWROOT/etc/hostname" 2>/dev/null || true

mount -t proc proc "$NEWROOT/proc"

cd "$NEWROOT"
pivot_root . oldroot
umount -l /oldroot
rmdir /oldroot 2>/dev/null || true
cd /

# Resource caps (rootless, no cgroup delegation needed): processes + address space.
ulimit -u 96 2>/dev/null || true        # RLIMIT_NPROC — fork-bomb guard
ulimit -v 4000000 2>/dev/null || true   # RLIMIT_AS (KB) — runaway-memory guard

export HOME=/scratch PWD=/scratch TMPDIR=/scratch PATH=/usr/bin:/bin
cd /scratch

# Drop the ability to gain privileges, then exec the payload.
exec setpriv --no-new-privs -- "$@"
