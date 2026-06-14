"""Landlock filesystem confinement — kernel-enforced, unprivileged, no mounts.

Landlock (Linux LSM, ABI since 5.13) lets an UNPRIVILEGED process irreversibly
restrict its own filesystem access to an explicit allowlist. Unlike the
bind-mount/pivot_root approach in confine_run.sh, it needs NO mount namespace
and NO root — so it works where sub-path RO binds are unsupported (e.g. WSL2)
and is exactly what OpenAI Codex and Sandlock use for fs confinement.

This module applies a ruleset to the CURRENT process (and its children): an
allowlist of read-only paths (system dirs, the signed policy) and read-write
paths (scratch). After `restrict_self`, anything outside the allowlist — host
secrets in /home, /root, /etc/shadow, other tenants' data — is unreadable and
unwritable, enforced by the kernel, irreversibly, with no way to opt back out.

Composes with the rest of Layer 1: run this INSIDE `unshare --net` (network
isolation) with rlimits + no-new-privs for the full sandbox. Landlock requires
no_new_privs, which we set here.

    # as a wrapper:
    python -m aegis.deploy.landlock_confine \
        --ro /usr --ro /bin --ro /lib --ro /lib64 --ro /etc \
        --ro /etc/aegis --rw /scratch -- /usr/bin/python3 agent.py

Fail-closed: if Landlock is unavailable (old kernel / disabled) the wrapper
REFUSES to exec the payload unless --allow-unconfined is passed (demo only).
Exit 3 = could not confine.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys

# x86_64 syscall numbers (also correct on most arches via the same names in
# recent glibc; we hardcode x86_64/arm64 which are the deployment targets).
_SYS = {
    "x86_64": (444, 445, 446),
    "aarch64": (444, 445, 446),
}

# landlock_access_fs bits
A_EXECUTE = 1 << 0
A_WRITE_FILE = 1 << 1
A_READ_FILE = 1 << 2
A_READ_DIR = 1 << 3
A_REMOVE_DIR = 1 << 4
A_REMOVE_FILE = 1 << 5
A_MAKE_CHAR = 1 << 6
A_MAKE_DIR = 1 << 7
A_MAKE_REG = 1 << 8
A_MAKE_SOCK = 1 << 9
A_MAKE_FIFO = 1 << 10
A_MAKE_BLOCK = 1 << 11
A_MAKE_SYM = 1 << 12
A_REFER = 1 << 13          # ABI 2
A_TRUNCATE = 1 << 14       # ABI 3

_READ_ACCESS = A_EXECUTE | A_READ_FILE | A_READ_DIR
_WRITE_ACCESS = (A_WRITE_FILE | A_REMOVE_DIR | A_REMOVE_FILE | A_MAKE_CHAR
                 | A_MAKE_DIR | A_MAKE_REG | A_MAKE_SOCK | A_MAKE_FIFO
                 | A_MAKE_BLOCK | A_MAKE_SYM)

LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
RULE_PATH_BENEATH = 1
PR_SET_NO_NEW_PRIVS = 38


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64),
                ("handled_access_net", ctypes.c_uint64)]


class _PathBeneathAttr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64),
                ("parent_fd", ctypes.c_int32)]


class LandlockUnavailable(Exception):
    pass


def _syscalls():
    arch = os.uname().machine
    if arch not in _SYS:
        raise LandlockUnavailable(f"unmapped arch {arch}")
    return _SYS[arch]


def _libc():
    return ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)


def abi_version() -> int:
    """Return the Landlock ABI version, or raise LandlockUnavailable."""
    libc = _libc()
    create, _, _ = _syscalls()
    v = libc.syscall(create, None, ctypes.c_size_t(0),
                     ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION))
    if v < 0:
        raise LandlockUnavailable(f"landlock_create_ruleset(version) errno={ctypes.get_errno()}")
    return v


def apply(ro_paths: list[str], rw_paths: list[str]) -> int:
    """Restrict the current process to the given allowlist. Returns the ABI
    version used. Raises LandlockUnavailable if Landlock can't be applied."""
    libc = _libc()
    create, add_rule, restrict = _syscalls()
    abi = abi_version()

    handled = _READ_ACCESS | _WRITE_ACCESS
    if abi >= 2:
        handled |= A_REFER
    if abi >= 3:
        handled |= A_TRUNCATE

    attr = _RulesetAttr(handled_access_fs=handled, handled_access_net=0)
    fd = libc.syscall(create, ctypes.byref(attr), ctypes.c_size_t(ctypes.sizeof(attr)),
                      ctypes.c_uint32(0))
    if fd < 0:
        raise LandlockUnavailable(f"create_ruleset errno={ctypes.get_errno()}")

    def _allow(path: str, access: int):
        try:
            dirfd = os.open(path, os.O_PATH | os.O_CLOEXEC)
        except OSError:
            return  # path absent on this host — skip (allowlist, so safe)
        try:
            pb = _PathBeneathAttr(allowed_access=access & handled, parent_fd=dirfd)
            rc = libc.syscall(add_rule, ctypes.c_int(fd), ctypes.c_int(RULE_PATH_BENEATH),
                              ctypes.byref(pb), ctypes.c_uint32(0))
            if rc != 0:
                raise LandlockUnavailable(f"add_rule({path}) errno={ctypes.get_errno()}")
        finally:
            os.close(dirfd)

    for p in ro_paths:
        _allow(p, _READ_ACCESS)
    for p in rw_paths:
        _allow(p, _READ_ACCESS | _WRITE_ACCESS)

    # Landlock requires no_new_privs.
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise LandlockUnavailable(f"prctl(NO_NEW_PRIVS) errno={ctypes.get_errno()}")
    if libc.syscall(restrict, ctypes.c_int(fd), ctypes.c_uint32(0)) != 0:
        raise LandlockUnavailable(f"restrict_self errno={ctypes.get_errno()}")
    os.close(fd)
    return abi


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Run a command under Landlock fs confinement")
    ap.add_argument("--ro", action="append", default=[], help="read-only allowed path")
    ap.add_argument("--rw", action="append", default=[], help="read-write allowed path")
    ap.add_argument("--allow-unconfined", action="store_true",
                    help="DEMO ONLY: exec even if Landlock is unavailable (default: fail-closed)")
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args(argv)
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        print("landlock_confine: no command (use -- cmd ...)", file=sys.stderr)
        return 2
    try:
        abi = apply(a.ro or ["/usr", "/bin", "/lib", "/lib64", "/etc"], a.rw or ["/scratch"])
        sys.stderr.write(f"[landlock] confined (ABI v{abi}); ro={a.ro} rw={a.rw}\n")
    except LandlockUnavailable as e:
        if a.allow_unconfined:
            sys.stderr.write(f"[landlock] UNAVAILABLE ({e}); proceeding UNCONFINED (demo)\n")
        else:
            sys.stderr.write(f"[landlock] cannot confine ({e}) — failing closed\n")
            return 3
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    sys.exit(main())
