"""Tiny helper to run q from Python for the OPTIONAL real-kdb+ tools/batteries.

NOT on the enforcement path - this is dev/ops tooling (the conformance battery
and the live schema-diff). The gate itself never shells out to q.

Design notes:
  * the q program is transferred base64-encoded, so NO shell quoting can break on
    backticks/spaces/semicolons in compiled q;
  * on Windows the command is auto-wrapped in `wsl` (q runs in WSL);
  * q is auto-found at $HOME/kdbx/l64/q, overridable via env.

Env (all optional):
    AEGIS_Q_BIN   path to the q binary   (default: $HOME/kdbx/l64/q)
    AEGIS_QHOME   QHOME                   (default: $HOME/kdbx)
    AEGIS_QLIC    QLIC dir (kc.lic)       (default: $HOME/kdbx)
"""

from __future__ import annotations

import base64
import os
import subprocess
import sys

Q_BIN = os.environ.get("AEGIS_Q_BIN", "$HOME/kdbx/l64/q")
QHOME = os.environ.get("AEGIS_QHOME", "$HOME/kdbx")
QLIC = os.environ.get("AEGIS_QLIC", "$HOME/kdbx")


def sh_prefix() -> list[str]:
    """Argv prefix to run a bash command string. On Windows q lives in WSL."""
    if sys.platform == "win32":
        return ["wsl", "-e", "bash", "-lc"]
    return ["bash", "-lc"]


def run_bash(cmd: str, timeout: int = 120) -> str:
    r = subprocess.run(sh_prefix() + [cmd], capture_output=True, text=True, timeout=timeout)
    return ((r.stdout or "") + (r.stderr or "")).strip()


def q_run(program: str, workdir: str = "/tmp/aegis_q", timeout: int = 120) -> str:
    """Run a q program (base64-transferred) and return its stdout+stderr. The
    program is responsible for printing its result and exiting."""
    b64 = base64.b64encode(program.encode("utf-8")).decode("ascii")
    cmd = (f"mkdir -p {workdir} && echo {b64} | base64 -d > {workdir}/prog.q && "
           f"QHOME={QHOME} QLIC={QLIC} {Q_BIN} {workdir}/prog.q -q")
    return run_bash(cmd, timeout)


def q_available() -> bool:
    try:
        return q_run("-1 .Q.s1 1+1; exit 0;", timeout=30).splitlines()[-1].strip() == "2"
    except Exception:
        return False
