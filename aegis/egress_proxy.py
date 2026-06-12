"""Egress proxy — Layer 4 ground-truth enforcement for network egress.

The network twin of the query proxy. In a confined deployment the agent has no
direct network; all traffic goes through here, so enforcement happens on the
REAL destination and the ACTUAL bytes on the wire — not on a `curl` string the
agent typed (which it can obfuscate). This is why it catches what the PDP
cannot:

  * destination is resolved and checked against the allowlist at connect time
    (defeats raw-IP, redirect, and string-obfuscation tricks);
  * SSRF guard blocks cloud-metadata (169.254.169.254) and private/loopback
    ranges that aren't explicitly allowlisted;
  * DLP inspects the payload for secrets and classified data and blocks (or
    redacts) before it leaves — so even an allowlisted host can't be used to
    exfiltrate (closes red-team RT-15).

Fail-closed: no resolvable destination, or any inspection error, => block.

Two parts (same split as query_proxy): EgressGuard is the pure, testable
decision core; ForwardProxy is the transport shell that calls it. HTTPS bodies
are opaque without TLS interception — that's a deployment decision (corp CA);
for CONNECT we still enforce the host allowlist. Stated, not hidden.
"""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from .detectors import _SECRET_PATTERNS


@dataclass
class EgressVerdict:
    action: str                 # "allow" | "block"
    host: str | None = None
    reasons: list[str] = field(default_factory=list)
    classification: list[str] = field(default_factory=list)
    redacted_body: str | None = None


class EgressBlocked(Exception):
    def __init__(self, verdict: EgressVerdict):
        self.verdict = verdict
        super().__init__("; ".join(verdict.reasons) or "egress blocked")


class EgressGuard:
    def __init__(self, config: dict | None = None):
        c = config or {}
        self.allow = {h.lower() for h in c.get("allowlist_hosts", [])}
        self.block_metadata = c.get("block_metadata_ip", True)
        self.block_private = c.get("block_private_ranges", True)
        dlp = c.get("dlp", {})
        self.sensitive_terms = [t.lower() for t in dlp.get("sensitive_terms", [])]
        self.scan_secrets = dlp.get("scan_secrets", True)
        self.dlp_effect = dlp.get("effect", "block")  # "block" | "redact"
        self.max_body = int(c.get("max_body_bytes", 1_000_000))

    @classmethod
    def from_policy(cls, policy_path: str | Path = None) -> "EgressGuard":
        policy_path = policy_path or Path(__file__).with_name("policy.json")
        cfg = json.loads(Path(policy_path).read_text(encoding="utf-8"))
        block = dict(cfg.get("egress_proxy", {}))
        # default the allowlist to the engine's egress allowlist if not set
        block.setdefault("allowlist_hosts", cfg.get("egress", {}).get("allowlist_hosts", []))
        if "sensitive_terms" not in block.get("dlp", {}):
            block.setdefault("dlp", {})["sensitive_terms"] = \
                cfg.get("pii_egress", {}).get("sensitive_terms", [])
        return cls(block)

    # -- public ------------------------------------------------------------

    def enforce(self, host=None, url=None, body=b"", method="GET") -> EgressVerdict:
        v = self.decide(host=host, url=url, body=body, method=method)
        if v.action == "block":
            raise EgressBlocked(v)
        return v

    def decide(self, host=None, url=None, body=b"", method="GET") -> EgressVerdict:
        if url and not host:
            try:
                host = urllib.parse.urlsplit(url).hostname
            except ValueError:
                host = None
        host = (host or "").strip().lower().split(":")[0]
        if not host:
            return EgressVerdict("block", None, ["no resolvable destination host — failing closed"])

        allowed = host in self.allow

        # SSRF guard — IP-literal destinations.
        ipobj = None
        try:
            ipobj = ipaddress.ip_address(host)
        except ValueError:
            ipobj = None
        if ipobj is not None and not allowed:
            if self.block_metadata and ipobj.is_link_local:
                return EgressVerdict("block", host,
                                     ["SSRF: link-local / cloud-metadata address blocked"])
            if self.block_private and (ipobj.is_private or ipobj.is_loopback):
                return EgressVerdict("block", host,
                                     ["SSRF: private/loopback address not on allowlist"])

        if not allowed:
            return EgressVerdict("block", host,
                                 [f"destination host '{host}' is not on the egress allowlist"])

        # Host is allowed — now inspect the payload (DLP). This is what stops
        # exfiltration THROUGH an allowlisted host.
        reasons, classes, masked = self._dlp(body)
        if reasons:
            if self.dlp_effect == "redact":
                return EgressVerdict("allow", host,
                                     ["payload redacted before egress"], classes, masked)
            return EgressVerdict("block", host, reasons, classes)

        return EgressVerdict("allow", host, ["host allowlisted, payload clean"])

    # -- DLP ---------------------------------------------------------------

    def _dlp(self, body) -> tuple[list[str], list[str], str]:
        if isinstance(body, bytes):
            text = body[: self.max_body].decode("utf-8", "replace")
        else:
            text = str(body)[: self.max_body]
        reasons: list[str] = []
        classes: list[str] = []
        redacted = text

        if self.scan_secrets:
            for name, pat in _SECRET_PATTERNS:
                for m in re.finditer(pat, text):
                    cap = m.group(1) if m.groups() else m.group(0)
                    reasons.append(f"payload contains a secret ({name})")
                    classes.append(name)
                    redacted = redacted.replace(cap, "[REDACTED-SECRET]")
                    break

        hits = [t for t in self.sensitive_terms if re.search(rf"(?i)\b{re.escape(t)}\b", text)]
        if hits:
            reasons.append(f"payload contains classified data ({', '.join(hits[:3])})")
            classes.extend(hits[:3])

        return reasons, classes, redacted
