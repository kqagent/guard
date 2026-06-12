"""Tamper-evident audit log.

Every decision is appended as one JSON line, hash-chained to the previous
entry (entry_hash = sha256(prev_hash + canonical(body))). Altering or
deleting any past entry breaks the chain from that point forward, which
`verify()` detects. This gives regulators a record that is cheap to write
and expensive to forge.

Hash-chaining alone is tamper-EVIDENT, not tamper-PROOF: an attacker who
controls the host can delete the file, or truncate it (a chain of the
surviving entries still verifies). So entries carry a monotonic `seq`, are
mirrored to an off-host append-only sink, and the chain head is anchored
externally — `verify_against_anchor` then catches truncation/rewind, and the
mirror preserves the record even if the local copy is destroyed. See
`AuditLog` for the mirror/anchor wiring (production targets: syslog collector,
HTTP append API, S3 Object-Lock / WORM bucket, KMS-held anchor).

Secrets are never written: detectors mask evidence before it reaches here.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

_GENESIS = "0" * 64


def _canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class AuditLog:
    """Hash-chained local log, optionally with an off-host mirror and an
    external anchor.

    - `mirror_path`: every entry is also appended here. In production this is a
      write-only off-host sink (syslog to a collector, an HTTP append API, an
      S3 Object-Lock / WORM bucket) the agent's host cannot edit. Destroying the
      local log then does not destroy the record.
    - `anchor_path`: stores the latest {seq, head}. Lets `verify_against_anchor`
      detect TRUNCATION / REWIND — which plain hash-chaining cannot, because a
      chain of the surviving entries still verifies. In production the anchor
      lives off-host (KMS, ledger, the collector's high-water mark).
    """

    def __init__(self, path: str | Path, mirror_path: str | Path | None = None,
                 anchor_path: str | Path | None = None,
                 sinks: list | None = None, strict_sinks: bool = False):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.mirror_path = Path(mirror_path) if mirror_path else None
        if self.mirror_path:
            self.mirror_path.parent.mkdir(parents=True, exist_ok=True)
        self.anchor_path = Path(anchor_path) if anchor_path else None
        if self.anchor_path:
            self.anchor_path.parent.mkdir(parents=True, exist_ok=True)
        # Off-host WORM sinks (see worm_sinks.py). strict_sinks=True makes a
        # failed delivery raise — "no record, no decision" for regulated
        # surfaces. Default is lenient: failures are counted, the gate runs.
        self.sinks = list(sinks) if sinks else []
        self.strict_sinks = strict_sinks
        self.sink_errors: list[str] = []

    def _tail(self) -> tuple[str, int]:
        """Return (last_entry_hash, last_seq) from the local log."""
        last_hash, last_seq = _GENESIS, -1
        if self.path.exists():
            with self.path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                        last_hash = e["entry_hash"]
                        last_seq = e.get("seq", last_seq)
                    except (json.JSONDecodeError, KeyError):
                        # A malformed line is itself a tamper signal; keep the
                        # last good values so verify() will flag the break.
                        pass
        return last_hash, last_seq

    def record(self, action, decision, principal: str | None = None) -> dict:
        prev, last_seq = self._tail()
        body = {
            "seq": last_seq + 1,
            "ts": datetime.now(timezone.utc).isoformat(),
            "principal": principal or action.principal or "unknown",
            "tool": action.tool,
            "surface": action.surface,
            "target": action.file_path or (action.command or "")[:200],
            "effect": decision.effect.value,
            "rules": [f.rule_id for f in decision.findings],
            "reasons": [f.reason for f in decision.findings],
        }
        entry_hash = hashlib.sha256((prev + _canonical(body)).encode("utf-8")).hexdigest()
        entry = {**body, "prev_hash": prev, "entry_hash": entry_hash}
        line = _canonical(entry)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        if self.mirror_path:  # off-host append-only copy (WORM / syslog / object-lock)
            with self.mirror_path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        if self.anchor_path:
            self.anchor_path.write_text(
                _canonical({"seq": body["seq"], "head": entry_hash}), encoding="utf-8")
        for sink in self.sinks:
            try:
                sink.append(line)
            except Exception as e:
                if self.strict_sinks:
                    raise
                self.sink_errors.append(f"seq={body['seq']} {type(e).__name__}: {e}")
        return entry

    def verify_against_anchor(self) -> tuple[bool, str]:
        """Detect truncation/rewind that the chain alone cannot: compare the
        local tail to the external anchor (fail-closed on any mismatch)."""
        if not self.anchor_path or not self.anchor_path.exists():
            return True, "no anchor configured"
        try:
            anchor = json.loads(self.anchor_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            return False, f"anchor unreadable ({type(e).__name__})"
        ok, _, err = self.verify()
        if not ok:
            return False, f"chain broken: {err}"
        last_hash, last_seq = self._tail()
        if last_seq < anchor["seq"]:
            gone = anchor["seq"] - last_seq
            return False, f"TRUNCATION: local seq {last_seq} < anchored {anchor['seq']} ({gone} entries destroyed)"
        if last_seq == anchor["seq"] and last_hash != anchor["head"]:
            return False, "REWRITE: head mismatch at anchored seq (history rewritten)"
        return True, f"local tail matches anchor (seq={last_seq})"

    def verify(self) -> tuple[bool, int, str | None]:
        """Walk the chain. Returns (ok, n_entries, error_or_none)."""
        if not self.path.exists():
            return True, 0, None
        prev = _GENESIS
        n = 0
        with self.path.open("r", encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                n += 1
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False, n, f"line {i}: not valid JSON (tampered/corrupt)"
                if entry.get("prev_hash") != prev:
                    return False, n, f"line {i}: prev_hash break (entry inserted/removed/reordered)"
                body = {k: entry[k] for k in entry if k not in ("prev_hash", "entry_hash")}
                expect = hashlib.sha256((prev + _canonical(body)).encode("utf-8")).hexdigest()
                if expect != entry.get("entry_hash"):
                    return False, n, f"line {i}: entry_hash mismatch (entry body altered)"
                prev = entry["entry_hash"]
        return True, n, None
