"""Proving battery for the approval workflow backend.

  1. grant path: agent blocks on wait(); an approver (separate thread,
     standing in for a separate process) grants via the same CLI code path;
     wait returns APPROVED and the ticket is single-use (consume()).
  2. deny path: explicit deny reaches the waiting agent.
  3. timeout => EXPIRED: silence never approves (fail-closed).
  4. decided tickets are immutable: a second decision raises.
  5. corrupt store => wait returns DENIED (fail-closed).

Run:  python -m aegis.approvals_test
"""

from __future__ import annotations

import sys
import tempfile
import threading
import time
from pathlib import Path

from .approvals import (APPROVED, DENIED, EXPIRED, ApprovalBroker,
                        ApprovalStore, main)

_checks: list[tuple[str, bool]] = []


def check(name: str, ok: bool) -> None:
    _checks.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}")


def run() -> int:
    print("=== approval workflow backend ===\n")
    tmp = Path(tempfile.mkdtemp(prefix="aegis_appr_"))
    store = ApprovalStore(tmp / "approvals.json")
    broker = ApprovalBroker(store)

    # 1. grant path, approver in another thread via the CLI entrypoint
    tid = broker.request("Bash", {"command": "q big_backfill.q"},
                         reason="RES-UNBOUNDED-SCAN", principal="etl-agent")

    import os
    os.environ["AEGIS_APPROVALS"] = str(tmp / "approvals.json")

    def approver():
        time.sleep(0.4)
        main(["grant", tid, "--by", "alice"])

    threading.Thread(target=approver, daemon=True).start()
    status = broker.wait(tid, timeout=10)
    check("waiting agent receives APPROVED from CLI grant", status == APPROVED)
    check("approved ticket consumes exactly once",
          store.consume(tid) and not store.consume(tid))
    t = store.get(tid)
    check("decision is attributed and timestamped",
          t["decided_by"] == "alice" and bool(t["decided_ts"]))

    # 2. explicit deny
    tid2 = broker.request("Bash", {"command": "rm -rf scratch"}, reason="DST")
    threading.Thread(target=lambda: (time.sleep(0.3), main(["deny", tid2, "--by", "bob"])),
                     daemon=True).start()
    check("explicit deny reaches the waiting agent",
          broker.wait(tid2, timeout=10) == DENIED)

    # 3. timeout: silence never approves
    tid3 = broker.request("Write", {"file_path": "src/x.q"}, reason="gate")
    status = broker.wait(tid3, timeout=0.6)
    check("timeout => EXPIRED, recorded as a deny", status == EXPIRED)
    check("expired ticket cannot be consumed", not store.consume(tid3))

    # 4. decided tickets are immutable
    try:
        store.decide(tid3, APPROVED, by="late-mallory")
        check("second decision on a decided ticket raises", False)
    except ValueError:
        check("second decision on a decided ticket raises", True)

    # 5. corrupt store fails closed
    (tmp / "approvals.json").write_text("{not json", encoding="utf-8")
    check("corrupt store => wait returns DENIED",
          broker.wait("whatever", timeout=0.5) == DENIED)

    failed = [n for n, ok in _checks if not ok]
    print(f"\n{'PASS' if not failed else 'FAIL'} — {len(_checks) - len(failed)}/{len(_checks)} checks")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(run())
