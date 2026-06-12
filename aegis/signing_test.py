"""Prove the integrity layer: a signed policy loads and runs; any tamper, wrong
key, or missing signature makes the engine fail CLOSED (block everything).

This is what makes "the agent cannot disable its guardrails" true at the crypto
level — even if the agent could WRITE policy.json, it cannot produce a valid
signature, so the PDP rejects it and blocks all actions.

Run:  python -m aegis.signing_test
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from . import signing
from .engine import Engine
from .model import Action, Effect

ALGO = "ed25519" if signing._HAVE_ED else "hmac-sha256"
BENIGN = Action(tool="Bash", tool_input={"command": "cat src/main.py"})


def run() -> int:
    print(f"=== Aegis integrity / policy signing (algo={ALGO}) ===\n")
    failures = 0
    real_policy = Path(__file__).with_name("policy.json")
    raw = real_policy.read_bytes()

    priv, pub = signing.generate_keypair(ALGO)
    _, pub_other = signing.generate_keypair(ALGO)  # an unrelated key

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        # The control function signs the real policy.
        sig_obj = signing.sign(raw, priv, ALGO)
        sig_path = tmp / "policy.json.sig"
        sig_path.write_text(__import__("json").dumps(sig_obj), encoding="utf-8")

        # 1) valid signature + correct pinned key -> loads clean, evaluates
        eng = Engine.load(real_policy, signature_path=sig_path, pinned_pubkey=pub, sig_algo=ALGO)
        ok1 = eng.load_error is None and eng.evaluate(BENIGN).effect is Effect.ALLOW
        failures += 0 if ok1 else 1
        print(f"  {'ok ' if ok1 else 'XX '} valid signature -> loads clean, benign action allowed")

        # 2) tampered policy (attacker disables all packs) + old signature
        tampered = raw.replace(b'"enabled_packs"', b'"enabled_packs_DISABLED"')
        tpolicy = tmp / "tampered.json"
        tpolicy.write_bytes(tampered)
        eng2 = Engine.load(tpolicy, signature_path=sig_path, pinned_pubkey=pub, sig_algo=ALGO)
        d2 = eng2.evaluate(BENIGN)
        ok2 = eng2.load_error is not None and d2.effect is Effect.BLOCK
        failures += 0 if ok2 else 1
        print(f"  {'ok ' if ok2 else 'XX '} tampered policy -> fail-closed (every action BLOCKED)")
        print(f"          {eng2.load_error}")

        # 3) correct policy + signature, but WRONG pinned key
        eng3 = Engine.load(real_policy, signature_path=sig_path, pinned_pubkey=pub_other, sig_algo=ALGO)
        ok3 = eng3.load_error is not None and eng3.evaluate(BENIGN).effect is Effect.BLOCK
        failures += 0 if ok3 else 1
        print(f"  {'ok ' if ok3 else 'XX '} wrong pinned key -> fail-closed")

        # 4) pinned key required but signature file missing
        eng4 = Engine.load(real_policy, signature_path=tmp / "nope.sig", pinned_pubkey=pub, sig_algo=ALGO)
        ok4 = eng4.load_error is not None and eng4.evaluate(BENIGN).effect is Effect.BLOCK
        failures += 0 if ok4 else 1
        print(f"  {'ok ' if ok4 else 'XX '} missing signature (key pinned) -> fail-closed")

    print(f"\n{'PASS' if failures == 0 else 'FAIL'} — {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(run())
