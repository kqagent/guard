"""The policy decision point (PDP).

Loads a signed policy bundle, runs the enabled detector packs against an
action, aggregates findings (most-severe-wins), and records the decision to
the tamper-evident audit log.

Fail-closed is the central safety property: if the policy is missing,
unparseable, or fails its integrity check, every action is BLOCKED. A gate
that fails open is not a gate.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .audit import AuditLog
from .detectors import DETECTORS
from .model import Action, Decision, Effect, Finding, most_severe


class Engine:
    def __init__(
        self,
        policy: dict | None,
        audit: AuditLog | None = None,
        load_error: str | None = None,
        mode: str | None = None,
    ):
        self.policy = policy or {}
        self.audit = audit
        self.load_error = load_error
        # "enforce" (default) blocks for real. "monitor" computes the verdict
        # and logs the would-be effect, but downgrades the ENFORCED effect to
        # ALLOW so nothing is blocked — for shadow rollout and measuring the
        # false-positive rate before flipping to enforce. Fail-closed
        # (load_error) is NOT downgraded; a broken policy still blocks.
        self.mode = mode or self.policy.get("mode", "enforce")

    # -- loading -----------------------------------------------------------

    @classmethod
    def load(
        cls,
        policy_path: str | Path,
        audit_path: str | Path | None = None,
        expected_sha256: str | None = None,
        pinned_pubkey: str | None = None,
        signature_path: str | Path | None = None,
        sig_algo: str | None = None,
    ) -> "Engine":
        """Load policy fail-closed.

        If anything is wrong with the bundle we still return an Engine, but
        one whose `load_error` is set — and `evaluate()` will BLOCK every
        action until a valid policy is in place.

        Integrity options (any failure => fail-closed):
        - `expected_sha256` pins the exact bundle (integrity).
        - `pinned_pubkey` requires a valid detached signature against that key
          (integrity + authenticity). The signature is read from
          `signature_path` (default `<policy>.sig`). The pinned key lives in
          the PDP's trusted config, never in the policy itself — that would be
          circular. This is what makes the guardrails unforgeable by the agent.
        """
        audit = AuditLog(audit_path) if audit_path else None
        path = Path(policy_path)
        try:
            raw = path.read_bytes()
        except OSError as e:
            return cls(None, audit, load_error=f"policy not readable: {e}")

        if expected_sha256:
            digest = hashlib.sha256(raw).hexdigest()
            if digest != expected_sha256:
                return cls(None, audit, load_error="policy integrity check failed (sha256 mismatch)")

        if pinned_pubkey is not None:
            from . import signing
            sig_file = Path(signature_path) if signature_path else path.with_name(path.name + ".sig")
            ok, reason = signing.verify_file(raw, sig_file, pinned_pubkey, sig_algo)
            if not ok:
                return cls(None, audit, load_error=f"policy signature verification failed: {reason}")

        try:
            policy = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            return cls(None, audit, load_error=f"policy not valid JSON: {e}")

        if not isinstance(policy, dict) or "enabled_packs" not in policy:
            return cls(None, audit, load_error="policy missing required 'enabled_packs'")

        return cls(policy, audit)

    # -- evaluation --------------------------------------------------------

    def evaluate(self, action: Action) -> Decision:
        if self.load_error is not None:
            decision = Decision(
                effect=Effect.BLOCK,
                findings=[Finding(
                    rule_id="ENGINE-FAIL-CLOSED",
                    effect=Effect.BLOCK,
                    pack="engine",
                    reason=f"policy unavailable, failing closed: {self.load_error}",
                    remediation="Restore a valid, integrity-checked policy bundle.",
                )],
            )
            self._audit(action, decision)
            return decision

        findings: list[Finding] = []
        for pack in self.policy.get("enabled_packs", []):
            detector = DETECTORS.get(pack)
            if detector is None:
                # Unknown pack named in policy: fail closed for that pack.
                findings.append(Finding(
                    rule_id="ENGINE-UNKNOWN-PACK",
                    effect=Effect.BLOCK,
                    pack="engine",
                    reason=f"policy enables unknown pack '{pack}'",
                    remediation="Remove the pack or install the detector that provides it.",
                ))
                continue
            try:
                findings.extend(detector(action, self.policy))
            except Exception as e:  # a buggy detector must not fail open
                findings.append(Finding(
                    rule_id="ENGINE-DETECTOR-ERROR",
                    effect=Effect.BLOCK,
                    pack="engine",
                    reason=f"detector '{pack}' raised {type(e).__name__}, failing closed",
                ))

        # Default-deny capability check. Only active when the policy declares
        # a "grants" block; otherwise the engine is detector-only (used by
        # unit tests). When active, an action that matches no grant is BLOCKED
        # regardless of whether any detector fired — this is the watertight
        # posture. Detectors remain a veto on *granted* actions.
        grants = self.policy.get("grants")
        if grants is not None:
            findings.extend(self._check_grants(action, grants))

        decided = most_severe([f.effect for f in findings])
        if self.mode == "monitor":
            # Don't block; record the would-be verdict for FP/FN analysis.
            decision = Decision(effect=Effect.ALLOW, findings=findings, shadow_effect=decided)
            self._audit(action, Decision(effect=decided, findings=findings, shadow_effect=decided))
        else:
            decision = Decision(effect=decided, findings=findings)
            self._audit(action, decision)
        return decision

    # -- default-deny --------------------------------------------------------

    @staticmethod
    def _under(file_path: str, prefix: str) -> bool:
        fp = file_path.replace("\\", "/").lstrip("./")
        pref = prefix.replace("\\", "/").rstrip("/").lstrip("./")
        return fp == pref or fp.startswith(pref + "/")

    def _check_grants(self, action: Action, grants: dict) -> list[Finding]:
        """Return BLOCK findings for any capability the action uses that the
        policy has not explicitly granted. Empty list => fully within grants."""
        import re

        out: list[Finding] = []

        tools = grants.get("tools")
        if tools is not None and action.tool not in tools:
            return [Finding(
                rule_id="DENY-TOOL-NOT-GRANTED", effect=Effect.BLOCK, pack="engine",
                reason=f"default-deny: tool '{action.tool}' is not in the capability grant",
                remediation="Add the tool to policy.grants.tools if it is approved.",
            )]

        if action.command is not None:
            bins = grants.get("binaries")
            if bins is not None:
                allowed = set(bins)
                for seg in re.split(r"[|;&]+", action.command):
                    seg = seg.strip()
                    if not seg:
                        continue
                    first = re.split(r"\s+", seg)[0]
                    if re.match(r"^\w+=", first):  # skip leading VAR=val env assignments
                        continue
                    binary = first.split("/")[-1]
                    if binary and binary not in allowed:
                        out.append(Finding(
                            rule_id="DENY-BINARY-NOT-GRANTED", effect=Effect.BLOCK, pack="engine",
                            reason=f"default-deny: binary '{binary}' is not allowlisted",
                            remediation="Add the binary to policy.grants.binaries if it is approved.",
                            evidence=binary,
                        ))
                        break

        if action.surface == "coding" and action.file_path:
            wp = grants.get("writable_paths")
            if wp is not None and not any(self._under(action.file_path, p) for p in wp):
                out.append(Finding(
                    rule_id="DENY-PATH-NOT-WRITABLE", effect=Effect.BLOCK, pack="engine",
                    reason=f"default-deny: '{action.file_path}' is not within a granted writable path",
                    remediation="Add the directory to policy.grants.writable_paths if approved.",
                    evidence=action.file_path,
                ))

        return out

    def _audit(self, action: Action, decision: Decision) -> None:
        if self.audit is not None:
            try:
                self.audit.record(action, decision, principal=action.principal)
            except Exception:
                # Audit failure should not crash the gate, but on a strict
                # bundle it should itself block. Keep PoC lenient; flag in log.
                pass
