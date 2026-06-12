"""Approval workflow backend for REQUIRE_APPROVAL decisions.

The engine can return Effect.REQUIRE_APPROVAL; in Claude Code that maps to
the built-in "ask" dialog, but a platform-API loop needs its own human gate.
This module is that gate: a file-backed ticket store plus a broker the agent
loop blocks on, and a CLI for the approver on the other side.

Flow:
    agent loop                    approver (human / change-control)
    ----------                    ---------------------------------
    decision = guard.check(...)
    REQUIRE_APPROVAL
      t = broker.request(...)     aegis-approve list
      broker.wait(t, timeout) --> aegis-approve grant <id> --by alice
      "approved" => execute       (or deny / or just let it time out)

Fail-closed properties:
  * wait() that times out returns DENIED (expired) — silence never approves.
  * A ticket store that cannot be read or written DENIES.
  * Tickets are single-use: once decided, re-waiting returns the decision,
    and a granted ticket can be consumed exactly once (consume()).

The store is a single JSON file guarded by an O_EXCL lock file, which is
portable (Windows/POSIX) and adequate for the human-latency rates an
approval queue sees. Swap ApprovalStore for a DB/ITSM adapter in production
(ServiceNow/Jira are the usual sinks) — Broker only needs get/put semantics.

CLI:  aegis-approve list | show <id> | grant <id> --by NAME | deny <id> --by NAME
Run the battery:  python -m aegis.approvals_test
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

PENDING = "pending"
APPROVED = "approved"
DENIED = "denied"
EXPIRED = "expired"   # a deny, reached by timeout rather than by a human
CONSUMED = "consumed"  # approved ticket already redeemed once


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ApprovalStore:
    """All tickets in one JSON file, mutated under an exclusive lock file."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = self.path.with_suffix(self.path.suffix + ".lock")

    # -- locking ------------------------------------------------------------

    def _acquire(self, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fd = os.open(self._lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(fd)
                return
            except FileExistsError:
                if time.monotonic() > deadline:
                    raise TimeoutError(f"approval store lock held: {self._lock}")
                time.sleep(0.05)

    def _release(self) -> None:
        try:
            os.unlink(self._lock)
        except OSError:
            pass

    # -- storage ------------------------------------------------------------

    def _read_all(self) -> dict:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8") or "{}")

    def _write_all(self, tickets: dict) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(tickets, indent=1, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.path)

    def create(self, ticket: dict) -> dict:
        self._acquire()
        try:
            tickets = self._read_all()
            tickets[ticket["id"]] = ticket
            self._write_all(tickets)
            return ticket
        finally:
            self._release()

    def get(self, ticket_id: str) -> dict | None:
        return self._read_all().get(ticket_id)

    def all(self) -> list[dict]:
        return sorted(self._read_all().values(), key=lambda t: t["created"])

    def decide(self, ticket_id: str, status: str, by: str, note: str = "") -> dict:
        """Transition a PENDING ticket. Deciding a non-pending ticket is an
        error — approvals are not retroactive and not reversible here."""
        self._acquire()
        try:
            tickets = self._read_all()
            t = tickets.get(ticket_id)
            if t is None:
                raise KeyError(f"no such ticket: {ticket_id}")
            if t["status"] != PENDING:
                raise ValueError(f"ticket {ticket_id} already {t['status']}")
            t.update(status=status, decided_by=by, decided_ts=_now(), note=note)
            self._write_all(tickets)
            return t
        finally:
            self._release()

    def consume(self, ticket_id: str) -> bool:
        """Atomically redeem an APPROVED ticket. True exactly once."""
        self._acquire()
        try:
            tickets = self._read_all()
            t = tickets.get(ticket_id)
            if t is None or t["status"] != APPROVED:
                return False
            t["status"] = CONSUMED
            t["consumed_ts"] = _now()
            self._write_all(tickets)
            return True
        finally:
            self._release()


class ApprovalBroker:
    """What the agent loop talks to. Wraps a store; never approves on its own."""

    def __init__(self, store: ApprovalStore):
        self.store = store

    def request(self, tool: str, tool_input: dict, reason: str,
                principal: str | None = None) -> str:
        """File a ticket for a REQUIRE_APPROVAL decision; returns ticket id."""
        target = (tool_input.get("file_path") or tool_input.get("command")
                  or json.dumps(tool_input, sort_keys=True))[:200]
        ticket = {
            "id": uuid.uuid4().hex[:12],
            "created": _now(),
            "principal": principal or "unknown",
            "tool": tool,
            "target": target,
            "reason": reason,
            "status": PENDING,
        }
        self.store.create(ticket)
        return ticket["id"]

    def wait(self, ticket_id: str, timeout: float = 300.0,
             poll: float = 0.25) -> str:
        """Block until the ticket is decided. Timeout => EXPIRED (a deny);
        an unreadable store => DENIED. Silence never approves."""
        deadline = time.monotonic() + timeout
        while True:
            try:
                t = self.store.get(ticket_id)
            except (OSError, json.JSONDecodeError):
                return DENIED
            if t is None:
                return DENIED
            if t["status"] != PENDING:
                return t["status"]
            if time.monotonic() >= deadline:
                try:
                    self.store.decide(ticket_id, EXPIRED, by="broker-timeout")
                except (ValueError, KeyError, OSError, TimeoutError):
                    pass  # raced with a late human decision; re-read below
                t = self.store.get(ticket_id)
                return t["status"] if t else DENIED
            time.sleep(poll)


# ---------------------------------------------------------------------------
# CLI — the approver's side
# ---------------------------------------------------------------------------

def _default_store() -> ApprovalStore:
    return ApprovalStore(os.environ.get("AEGIS_APPROVALS", ".aegis/approvals.json"))


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(__doc__.split("CLI:")[1].strip() if "CLI:" in (__doc__ or "")
              else "list | show <id> | grant <id> --by NAME | deny <id> --by NAME")
        print("store: $AEGIS_APPROVALS (default .aegis/approvals.json)")
        return 0
    store = _default_store()
    cmd = args[0]
    if cmd == "list":
        rows = store.all()
        if not rows:
            print("(no tickets)")
        for t in rows:
            print(f"{t['id']}  {t['status']:<9} {t['principal']:<14} "
                  f"{t['tool']:<10} {t['target'][:60]}")
        return 0
    if cmd == "show" and len(args) >= 2:
        t = store.get(args[1])
        print(json.dumps(t, indent=2) if t else f"no such ticket: {args[1]}")
        return 0 if t else 1
    if cmd in ("grant", "deny") and len(args) >= 2:
        by = "cli"
        if "--by" in args:
            by = args[args.index("--by") + 1]
        try:
            t = store.decide(args[1], APPROVED if cmd == "grant" else DENIED, by=by)
        except (KeyError, ValueError) as e:
            print(f"error: {e}")
            return 1
        print(f"{t['id']} -> {t['status']} (by {by})")
        return 0
    print(f"unknown command: {' '.join(args)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
