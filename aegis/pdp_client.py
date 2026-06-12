"""Client for the out-of-process PDP. Fail-closed by construction.

Any failure to get a clean verdict from the PDP — connection refused, timeout,
non-200, unparseable body — returns a BLOCK. A broker that cannot reach its
decision point must not let the action through.

`RemotePDP` duck-types `Engine.evaluate(action) -> Decision`, so it drops into
`Guard` unchanged: `Guard.remote("http://127.0.0.1:8787")`.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from .model import Action, Decision, Effect, Finding


class RemotePDP:
    def __init__(self, endpoint: str, timeout: float = 5.0):
        self.endpoint = endpoint.rstrip("/")
        self.timeout = timeout

    def evaluate(self, action: Action) -> Decision:
        payload = json.dumps({
            "tool": action.tool,
            "tool_input": action.tool_input,
            "principal": action.principal,
            "cwd": action.cwd,
        }).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint + "/v1/evaluate",
            data=payload,
            headers={"content-type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status != 200:
                    return self._fail(f"PDP returned HTTP {resp.status}")
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return self._fail(f"PDP HTTP {e.code} — failing closed")
        except Exception as e:
            return self._fail(f"PDP unreachable ({type(e).__name__}) — failing closed")
        return self._from_dict(data)

    @staticmethod
    def _fail(reason: str) -> Decision:
        return Decision(Effect.BLOCK, [Finding(
            rule_id="PDP-UNREACHABLE", effect=Effect.BLOCK, pack="pdp_client",
            reason=reason,
            remediation="Ensure the PDP sidecar is running and reachable.",
        )])

    @staticmethod
    def _from_dict(data: dict) -> Decision:
        findings = [Finding(
            rule_id=f.get("rule_id", "?"),
            effect=Effect(f.get("effect", "block")),
            reason=f.get("reason", ""),
            pack=f.get("pack", ""),
            remediation=f.get("remediation", ""),
            evidence=f.get("evidence", ""),
        ) for f in data.get("findings", [])]
        try:
            effect = Effect(data["effect"])
        except (KeyError, ValueError):
            return RemotePDP._fail("PDP returned malformed verdict — failing closed")
        return Decision(effect, findings)
