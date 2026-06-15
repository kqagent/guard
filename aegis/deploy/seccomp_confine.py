"""seccomp-bpf syscall confinement — stdlib-only, hand-assembled BPF.

Namespaces + Landlock restrict *what the process can name* (mounts, files, net).
They do NOT reduce the *kernel attack surface*: a confined process can still call
every syscall, so a kernel bug reachable via `bpf`, `perf_event_open`,
`userfaultfd`, `ptrace`, or a container-escape primitive (`mount`, `setns`,
`pivot_root`, `init_module`, `kexec_load`) is still reachable. This is the gap
the deep-research flagged versus gVisor/microVM isolation: those interpose on
syscalls; raw namespaces don't.

This module installs a seccomp-bpf filter that closes that gap from raw kernel
primitives, with NO third-party dep (no libseccomp) - just ctypes + a BPF program
assembled by hand. It is a DENY-LIST of clearly-dangerous syscalls (privilege
escalation, namespace/mount manipulation, kernel-module loading, kernel-replace,
debugging of other processes, host-state changes). A legitimate analyst payload
(python + a kdb+ client) never issues these.

Honest scope: a deny-list is weaker than an allow-list (a novel or un-listed
dangerous syscall slips through) and seccomp is NOT a substitute for a microVM
against a kernel 0-day. It RAISES THE BAR materially and composes with the rest
of Layer 1; for adversarial multi-tenant, still run inside a microVM (see
MICROVM.md). For a default-allow allow-list variant, see `--mode allowlist`.

    # as a wrapper, after unshare/landlock:
    python -m aegis.deploy.seccomp_confine -- /usr/bin/python3 agent.py

Fail-closed: if the filter cannot be installed (old kernel / unsupported arch)
the wrapper REFUSES to exec unless --allow-unconfined (demo only). Exit 3.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import struct
import sys

# --- BPF / seccomp constants ---------------------------------------------
BPF_LD = 0x00
BPF_W = 0x00
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_K = 0x00
BPF_RET = 0x06

LD_W_ABS = BPF_LD | BPF_W | BPF_ABS      # 0x20
JEQ_K = BPF_JMP | BPF_JEQ | BPF_K        # 0x15
RET_K = BPF_RET | BPF_K                  # 0x06

SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000

# offsets into struct seccomp_data { int nr; __u32 arch; __u64 ip; __u64 args[6]; }
OFF_NR = 0
OFF_ARCH = 4

AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7

PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

ARCH_AUDIT = {"x86_64": AUDIT_ARCH_X86_64, "aarch64": AUDIT_ARCH_AARCH64}

# Dangerous syscalls, by name -> (x86_64 nr, aarch64 nr). None = not on that arch.
# Curated: privilege escalation, namespace/mount manipulation (escape), kernel
# module load, kernel replace, cross-process debugging/memory, host-state, and
# fs-handle escape. A normal confined analyst payload issues none of these.
DANGEROUS: dict[str, tuple[int | None, int | None]] = {
    # cross-process debugging / memory
    "ptrace": (101, 117),
    "process_vm_readv": (310, 270),
    "process_vm_writev": (311, 271),
    # namespace / mount manipulation -> container escape
    "mount": (165, 40),
    "umount2": (166, 39),
    "pivot_root": (155, 41),
    "chroot": (161, 51),
    "setns": (308, 268),
    "unshare": (272, 97),
    "open_tree": (428, 428),
    "move_mount": (429, 429),
    "mount_setattr": (442, 442),
    "fsopen": (430, 430),
    "fsmount": (432, 432),
    # kernel modules / kernel replace
    "init_module": (175, 105),
    "finit_module": (313, 273),
    "delete_module": (176, 106),
    "kexec_load": (246, 104),
    "kexec_file_load": (320, 294),
    # kernel attack surface / exploit primitives
    "bpf": (321, 280),
    "perf_event_open": (298, 241),
    "userfaultfd": (323, 282),
    # kernel keyring
    "add_key": (248, 217),
    "keyctl": (250, 219),
    "request_key": (249, 218),
    # host state
    "swapon": (167, 224),
    "swapoff": (168, 225),
    "reboot": (169, 142),
    "acct": (163, 89),
    "settimeofday": (164, None),
    "clock_settime": (227, 112),
    # fs-handle escape (reopen a path by handle, bypassing the path allowlist)
    "open_by_handle_at": (304, 265),
    "name_to_handle_at": (303, 264),
    # x86 I/O-port / LDT privilege
    "ioperm": (173, None),
    "iopl": (172, None),
    "modify_ldt": (154, None),
}


class SeccompUnavailable(Exception):
    pass


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(_SockFilter))]


def _libc():
    return ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)


def blocked_for_arch(arch: str) -> dict[str, int]:
    """Name -> syscall-nr map of the dangerous syscalls that exist on `arch`."""
    idx = 0 if arch == "x86_64" else 1
    if arch not in ARCH_AUDIT:
        raise SeccompUnavailable(f"unsupported arch {arch}")
    return {name: nrs[idx] for name, nrs in DANGEROUS.items() if nrs[idx] is not None}


def build_program(arch: str, on_violation: int = SECCOMP_RET_KILL_PROCESS) -> list[tuple]:
    """Assemble the BPF program as a list of (code, jt, jf, k) tuples.

    Shape:
        LD  arch
        JEQ <this arch> ? skip kill : kill      (block syscall-number confusion)
        LD  nr
        for each dangerous nr:
            JEQ nr ? fall-through to deny : skip deny
            RET <on_violation>
        RET ALLOW
    """
    audit = ARCH_AUDIT[arch]
    prog: list[tuple] = []
    # validate arch: mismatch -> KILL (an i386/x32 caller can't smuggle a syscall)
    prog.append((LD_W_ABS, 0, 0, OFF_ARCH))
    prog.append((JEQ_K, 1, 0, audit))            # arch == audit -> skip the kill
    prog.append((RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS))
    prog.append((LD_W_ABS, 0, 0, OFF_NR))
    for nr in blocked_for_arch(arch).values():
        prog.append((JEQ_K, 0, 1, nr))           # nr matches -> next instr (deny); else skip it
        prog.append((RET_K, 0, 0, on_violation))
    prog.append((RET_K, 0, 0, SECCOMP_RET_ALLOW))
    return prog


def _pack(prog: list[tuple]) -> bytes:
    return b"".join(struct.pack("HBBI", *ins) for ins in prog)


def apply(on_violation: int = SECCOMP_RET_KILL_PROCESS) -> int:
    """Install the seccomp filter on the current process (irreversible, inherited
    across exec/fork). Returns the number of dangerous syscalls blocked. Raises
    SeccompUnavailable if the filter cannot be installed."""
    arch = os.uname().machine
    if arch not in ARCH_AUDIT:
        raise SeccompUnavailable(f"unsupported arch {arch} (no syscall table)")
    prog = build_program(arch, on_violation)
    blob = _pack(prog)
    n = len(prog)
    arr = (_SockFilter * n).from_buffer_copy(blob)
    fprog = _SockFprog(len=n, filter=arr)

    libc = _libc()
    # seccomp filter mode needs no_new_privs unless CAP_SYS_ADMIN.
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise SeccompUnavailable(f"prctl(NO_NEW_PRIVS) errno={ctypes.get_errno()}")
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog), 0, 0) != 0:
        raise SeccompUnavailable(f"prctl(SET_SECCOMP) errno={ctypes.get_errno()}")
    return len(blocked_for_arch(arch))


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Run a command under a seccomp-bpf syscall deny-list")
    ap.add_argument("--on-violation", choices=["kill", "errno"], default="kill",
                    help="kill the process (default) or return EPERM on a blocked syscall")
    ap.add_argument("--allow-unconfined", action="store_true",
                    help="DEMO ONLY: exec even if seccomp is unavailable (default: fail-closed)")
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args(argv)
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        print("seccomp_confine: no command (use -- cmd ...)", file=sys.stderr)
        return 2
    action = SECCOMP_RET_KILL_PROCESS if a.on_violation == "kill" else (SECCOMP_RET_ERRNO | 1)
    try:
        n = apply(action)
        sys.stderr.write(f"[seccomp] filter installed; {n} dangerous syscalls blocked "
                         f"(on-violation={a.on_violation})\n")
    except SeccompUnavailable as e:
        if a.allow_unconfined:
            sys.stderr.write(f"[seccomp] UNAVAILABLE ({e}); proceeding UNCONFINED (demo)\n")
        else:
            sys.stderr.write(f"[seccomp] cannot confine ({e}) — failing closed\n")
            return 3
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    sys.exit(main())
