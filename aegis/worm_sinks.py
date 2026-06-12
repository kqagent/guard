"""Concrete WORM sink adapters for the audit log.

`audit.AuditLog` already supports a `mirror_path` (an append-only file the
agent host treats as off-host). These adapters make the "off-host" part real:
each one delivers every audit line to a sink the agent's uid cannot rewrite.

    SyslogSink     RFC 3164 UDP datagram to a syslog collector. Fire-and-
                   forget transport; the collector is the WORM store.
    HTTPSink       POST each entry to an append-only HTTP API (e.g. a
                   collector in front of S3 Object-Lock). stdlib urllib.
    FileSink       append to a file — for a kernel-enforced WORM mount
                   (chattr +a / object-lock NFS) and for tests.
    S3ObjectLockSink
                   one object per entry in a bucket with Object Lock
                   (compliance mode). Needs boto3 — imported lazily; a
                   missing boto3 raises at CONSTRUCTION (config error,
                   fail-closed), never silently at write time.

Delivery semantics: sinks are called inline on every record. By default a
sink failure is counted (`AuditLog.sink_errors`) but does not break the
gate — availability of the decision path wins. For regulated surfaces pass
`strict_sinks=True` to AuditLog: then a failed sink raises, and the engine's
audit wrapper turns that into a blocked action (no decision without a
record). Choose per deployment; the default is the lenient PoC posture.
"""

from __future__ import annotations

import socket
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


class SinkError(Exception):
    """A sink could not durably accept an audit line."""


class SyslogSink:
    """RFC 3164-framed UDP datagram per audit line.

    UDP is lossy by nature; this sink is for feeding an existing syslog
    pipeline where the collector implements durability. For guaranteed
    delivery use HTTPSink against an acking endpoint.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 514,
                 facility: int = 13, app: str = "aegis-audit"):
        self.addr = (host, port)
        self.facility = facility
        self.app = app
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def append(self, line: str) -> None:
        pri = self.facility * 8 + 6  # severity: informational
        ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        msg = f"<{pri}>{ts} {self.app}: {line}"
        try:
            self._sock.sendto(msg.encode("utf-8"), self.addr)
        except OSError as e:
            raise SinkError(f"syslog send failed: {e}") from e


class HTTPSink:
    """POST each audit line to an append-only HTTP endpoint.

    The endpoint contract is intentionally tiny: POST body = one audit line,
    2xx = durably accepted. Anything else (including network failure) is a
    SinkError. Put your WORM semantics behind the endpoint (S3 Object-Lock,
    immudb, a ledger DB) — the gate host only ever holds an append handle.
    """

    def __init__(self, url: str, headers: dict | None = None, timeout: float = 5.0):
        self.url = url
        self.headers = {"content-type": "application/x-ndjson", **(headers or {})}
        self.timeout = timeout

    def append(self, line: str) -> None:
        req = urllib.request.Request(self.url, data=line.encode("utf-8"),
                                     headers=self.headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if not (200 <= resp.status < 300):
                    raise SinkError(f"HTTP sink returned {resp.status}")
        except SinkError:
            raise
        except Exception as e:
            raise SinkError(f"HTTP sink unreachable ({type(e).__name__})") from e


class FileSink:
    """Append to a file. Real WORM only if the mount enforces it (chattr +a,
    object-lock NFS, read-only-after-rotate); also the test double."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, line: str) -> None:
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError as e:
            raise SinkError(f"file sink write failed: {e}") from e


class S3ObjectLockSink:
    """One immutable object per audit entry in an Object-Lock bucket.

    S3 has no append, so WORM-correct usage is object-per-entry:
    `<prefix>/<seq from the entry, zero-padded>-<entry_hash>.json` written
    with the bucket's Object Lock retention (compliance mode). Key layout
    makes truncation as evident as the anchor does locally: a missing seq
    is a hole.

    boto3 is NOT a dependency of the enforcement path; it is imported here,
    at construction, and a missing boto3 is a loud config error.
    """

    def __init__(self, bucket: str, prefix: str = "aegis-audit/",
                 retention_days: int | None = None, client=None):
        if client is None:
            try:
                import boto3
            except ImportError as e:
                raise SinkError(
                    "S3ObjectLockSink requires boto3 (pip install boto3); "
                    "refusing to configure a WORM sink that cannot deliver"
                ) from e
            client = boto3.client("s3")
        self.client = client
        self.bucket = bucket
        self.prefix = prefix
        self.retention_days = retention_days

    def append(self, line: str) -> None:
        import json
        try:
            entry = json.loads(line)
            key = f"{self.prefix}{int(entry.get('seq', 0)):012d}-{entry.get('entry_hash', 'nohash')[:16]}.json"
        except (json.JSONDecodeError, ValueError, TypeError):
            key = f"{self.prefix}malformed-{abs(hash(line)) % 10**12:012d}.json"
        kwargs = {"Bucket": self.bucket, "Key": key, "Body": line.encode("utf-8")}
        if self.retention_days is not None:
            from datetime import timedelta
            kwargs["ObjectLockMode"] = "COMPLIANCE"
            kwargs["ObjectLockRetainUntilDate"] = (
                datetime.now(timezone.utc) + timedelta(days=self.retention_days))
        try:
            self.client.put_object(**kwargs)
        except Exception as e:
            raise SinkError(f"S3 put_object failed ({type(e).__name__})") from e
