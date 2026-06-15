"""Prove the seccomp-bpf confinement: the hand-assembled BPF program is
well-formed (cross-platform, structural) AND, on Linux, actually blocks a
dangerous syscall in the kernel while leaving benign syscalls working.

The structural half runs anywhere (it only inspects the BPF tuples), so it is a
CORE check. The kernel half runs only where seccomp can be applied (Linux, e.g.
a prod box or WSL); on Windows it is skipped and the structural proof stands.

Run:  python -m aegis.seccomp_test
On a Linux box / WSL you get the real kernel-enforcement proof too.
"""

from __future__ import annotations

import os
import sys

from aegis.deploy.seccomp_confine import (
    AUDIT_ARCH_AARCH64,
    AUDIT_ARCH_X86_64,
    JEQ_K,
    LD_W_ABS,
    OFF_ARCH,
    OFF_NR,
    RET_K,
    SECCOMP_RET_ALLOW,
    SECCOMP_RET_ERRNO,
    SECCOMP_RET_KILL_PROCESS,
    apply,
    blocked_for_arch,
    build_program,
)


def _structural(check) -> None:
    prog = build_program("x86_64")
    blocked = blocked_for_arch("x86_64")

    check("arch is loaded first (offset 4)", prog[0] == (LD_W_ABS, 0, 0, OFF_ARCH), prog[0])
    check("arch is verified against AUDIT_ARCH_X86_64",
          prog[1] == (JEQ_K, 1, 0, AUDIT_ARCH_X86_64), prog[1])
    check("arch mismatch -> KILL (no x32/i386 syscall smuggling)",
          prog[2] == (RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS), prog[2])
    check("syscall nr is loaded next (offset 0)", prog[3] == (LD_W_ABS, 0, 0, OFF_NR), prog[3])
    check("program ends with default-ALLOW", prog[-1] == (RET_K, 0, 0, SECCOMP_RET_ALLOW), prog[-1])
    check("program size is 4 header + 2 per blocked syscall + 1 allow",
          len(prog) == 4 + 2 * len(blocked) + 1, len(prog))

    # every dangerous syscall has a JEQ(nr) immediately followed by a deny RET.
    body = prog[4:-1]
    pairs = {body[i][3]: body[i + 1] for i in range(0, len(body), 2)
             if body[i][0] == JEQ_K and body[i][1] == 0 and body[i][2] == 1}
    missing = [name for name, nr in blocked.items() if nr not in pairs]
    check("every dangerous syscall has a guard (JEQ nr -> deny)", not missing, f"missing {missing}")
    bad_deny = [nr for nr, ins in pairs.items() if ins != (RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS)]
    check("every guard denies with KILL by default", not bad_deny, f"non-kill deny for nr {bad_deny}")

    # spot-check that the headline escape/priv syscalls are actually covered.
    for name in ("ptrace", "mount", "setns", "unshare", "init_module", "bpf",
                 "kexec_load", "perf_event_open", "pivot_root"):
        check(f"blocks {name}", blocked.get(name) in pairs, blocked.get(name))

    # errno mode encodes SECCOMP_RET_ERRNO | EPERM in the deny RET.
    eprog = build_program("x86_64", on_violation=SECCOMP_RET_ERRNO | 1)
    check("errno mode encodes EPERM deny", (RET_K, 0, 0, SECCOMP_RET_ERRNO | 1) in eprog,
          "no EPERM deny found")

    # aarch64 uses a different audit token and its own syscall numbers.
    a64 = build_program("aarch64")
    check("aarch64 program verifies AUDIT_ARCH_AARCH64",
          a64[1] == (JEQ_K, 1, 0, AUDIT_ARCH_AARCH64), a64[1])
    check("aarch64 ptrace nr (117) differs from x86_64 (101)",
          blocked_for_arch("aarch64")["ptrace"] == 117 and blocked["ptrace"] == 101)


def _fork_apply(action: int, attempt) -> tuple[int, int]:
    """Fork; in the child install the seccomp filter then run `attempt`. Returns
    (exit_code, term_signal) of the child."""
    pid = os.fork()
    if pid == 0:                      # child
        try:
            apply(action)
            attempt()
            os._exit(0)
        except SystemExit:
            raise
        except BaseException:
            os._exit(99)
    _, status = os.waitpid(pid, 0)
    if os.WIFSIGNALED(status):
        return (-1, os.WTERMSIG(status))
    return (os.WEXITSTATUS(status), 0)


def _kernel(check) -> None:
    import ctypes
    import ctypes.util
    import signal

    CLONE_NEWUSER = 0x10000000
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    libc.syscall.restype = ctypes.c_long
    unshare_nr = blocked_for_arch(os.uname().machine)["unshare"]

    # 1. benign syscalls still work after the filter is installed.
    def benign():
        os.getpid()
        with open(os.devnull, "wb") as fh:
            fh.write(b"ok")          # write() is not blocked
    code, sig = _fork_apply(SECCOMP_RET_KILL_PROCESS, benign)
    check("kernel: benign syscalls run normally under the filter", (code, sig) == (0, 0), f"code={code} sig={sig}")

    # 2. a blocked syscall (unshare) is KILLed by the kernel with SIGSYS.
    def do_unshare():
        libc.syscall(ctypes.c_long(unshare_nr), ctypes.c_long(CLONE_NEWUSER))
    code, sig = _fork_apply(SECCOMP_RET_KILL_PROCESS, do_unshare)
    check("kernel: blocked `unshare` is KILLed with SIGSYS", sig == signal.SIGSYS, f"code={code} sig={sig}")

    # 3. errno mode: the same syscall returns EPERM instead of killing.
    def unshare_expect_eperm():
        rc = libc.syscall(ctypes.c_long(unshare_nr), ctypes.c_long(CLONE_NEWUSER))
        # -1 with EPERM; signal a clean, distinct exit code so the parent can tell.
        os._exit(42 if rc == -1 else 7)
    code, sig = _fork_apply(SECCOMP_RET_ERRNO | 1, unshare_expect_eperm)
    check("kernel: errno mode returns EPERM (survives, no kill)", (code, sig) == (42, 0), f"code={code} sig={sig}")


def run() -> int:
    fails = 0

    def check(name, cond, detail=""):
        nonlocal fails
        print(f"  {'ok ' if cond else 'XX '} {name}")
        if not cond:
            fails += 1
            if detail != "":
                print(f"        {detail}")

    print("structural (BPF program well-formedness):")
    _structural(check)

    if sys.platform.startswith("linux") and hasattr(os, "fork"):
        print("kernel (real seccomp enforcement):")
        try:
            _kernel(check)
        except Exception as e:
            check("kernel enforcement test ran", False, f"unexpected error: {e!r}")
    else:
        print(f"kernel enforcement: SKIP (not Linux: {sys.platform}) — structural proof stands")

    print(f"\n{'PASS' if fails == 0 else 'FAIL'} — {fails} failure(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(run())
