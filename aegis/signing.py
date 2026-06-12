"""Policy signing & verification — the integrity layer.

Makes "the agent cannot disable its own guardrails" true at the crypto level,
not via a regex on a protected path. The control function signs the policy
bundle with a PRIVATE key it alone holds (ideally in an HSM/KMS). The PDP is
started with only the PUBLIC key, pinned in its trusted config. If the policy
is altered by anyone — an insider with repo write, the agent, a supply-chain
tamper — the signature no longer verifies and the engine fails closed (blocks
everything) until a validly re-signed bundle is in place.

Asymmetric (Ed25519) is the real control: whoever can VERIFY cannot FORGE.
HMAC-SHA256 is a stdlib fallback for environments without `cryptography`; it is
symmetric (the verifier holds the signing secret) so it gives integrity but not
separation-of-duties — use Ed25519 in production.

Defense in depth: signing complements a read-only mount of the bundle (OS
permissions the agent's uid lacks). Either alone helps; together the policy is
neither writable nor forgeable from the agent's domain.

CLI:
    python -m aegis.signing keygen --algo ed25519 --out-dir .
    python -m aegis.signing sign   --policy aegis/policy.json --key signing_key.pem
    python -m aegis.signing verify --policy aegis/policy.json --sig aegis/policy.json.sig --pub <hex>
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.exceptions import InvalidSignature
    _HAVE_ED = True
except Exception:  # pragma: no cover - environment without cryptography
    _HAVE_ED = False


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# -- key generation --------------------------------------------------------

def generate_keypair(algo: str = "ed25519") -> tuple[str, str]:
    """Return (private_material, public_material) as strings.
    ed25519: (PEM private key, hex raw public key).
    hmac-sha256: (hex secret, same hex secret) — symmetric."""
    if algo == "ed25519":
        if not _HAVE_ED:
            raise RuntimeError("ed25519 requested but `cryptography` is not installed")
        priv = Ed25519PrivateKey.generate()
        pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8")
        pub_hex = priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        return pem, pub_hex
    if algo == "hmac-sha256":
        secret = os.urandom(32).hex()
        return secret, secret
    raise ValueError(f"unknown algo '{algo}'")


# -- signing ---------------------------------------------------------------

def sign(policy_bytes: bytes, private_material: str, algo: str = "ed25519") -> dict:
    sha = _sha256_hex(policy_bytes)
    if algo == "ed25519":
        if not _HAVE_ED:
            raise RuntimeError("ed25519 requested but `cryptography` is not installed")
        priv = serialization.load_pem_private_key(private_material.encode("utf-8"), password=None)
        sig = priv.sign(policy_bytes).hex()
        pub_hex = priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        key_id = hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()[:12]
    elif algo == "hmac-sha256":
        sig = hmac.new(bytes.fromhex(private_material), policy_bytes, hashlib.sha256).hexdigest()
        key_id = hashlib.sha256(private_material.encode()).hexdigest()[:12]
    else:
        raise ValueError(f"unknown algo '{algo}'")
    return {"algo": algo, "key_id": key_id, "sha256": sha, "sig": sig}


# -- verification (fail-closed) --------------------------------------------

def verify(policy_bytes: bytes, sig_obj: dict, pinned_public: str,
           algo: str | None = None) -> tuple[bool, str]:
    """Return (ok, reason). ok=False on ANY problem — caller fails closed."""
    if not isinstance(sig_obj, dict):
        return False, "signature object malformed"
    algo = algo or sig_obj.get("algo")
    if _sha256_hex(policy_bytes) != sig_obj.get("sha256"):
        return False, "policy bytes differ from what was signed (sha256 mismatch)"
    sig_hex = sig_obj.get("sig", "")

    if algo == "ed25519":
        if not _HAVE_ED:
            return False, "ed25519 signature but `cryptography` unavailable — failing closed"
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pinned_public))
            pub.verify(bytes.fromhex(sig_hex), policy_bytes)
            return True, "ed25519 signature valid"
        except (InvalidSignature, ValueError) as e:
            return False, f"ed25519 verification failed: {type(e).__name__}"
    if algo == "hmac-sha256":
        expected = hmac.new(bytes.fromhex(pinned_public), policy_bytes, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, sig_hex):
            return True, "hmac signature valid"
        return False, "hmac verification failed"
    return False, f"unknown or unpinned algo '{algo}'"


def verify_file(policy_bytes: bytes, sig_path: str | Path, pinned_public: str,
                algo: str | None = None) -> tuple[bool, str]:
    sig_path = Path(sig_path)
    if not sig_path.exists():
        return False, f"signature file missing ({sig_path.name}) — failing closed"
    try:
        sig_obj = json.loads(sig_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        return False, f"signature file unreadable: {type(e).__name__}"
    return verify(policy_bytes, sig_obj, pinned_public, algo)


# -- CLI -------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Aegis policy signing")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen")
    g.add_argument("--algo", default="ed25519", choices=["ed25519", "hmac-sha256"])
    g.add_argument("--out-dir", default=".")

    s = sub.add_parser("sign")
    s.add_argument("--policy", required=True)
    s.add_argument("--key", required=True)
    s.add_argument("--algo", default="ed25519")
    s.add_argument("--out", default=None)

    v = sub.add_parser("verify")
    v.add_argument("--policy", required=True)
    v.add_argument("--sig", required=True)
    v.add_argument("--pub", required=True)
    v.add_argument("--algo", default=None)

    args = ap.parse_args()

    if args.cmd == "keygen":
        priv, pub = generate_keypair(args.algo)
        out = Path(args.out_dir)
        key_path = out / ("signing_key.pem" if args.algo == "ed25519" else "signing_key.hex")
        key_path.write_text(priv, encoding="utf-8")
        (out / "signing_pub.hex").write_text(pub, encoding="utf-8")
        print(f"wrote {key_path} (KEEP SECRET) and {out/'signing_pub.hex'}")
        print(f"public (pin this in the PDP): {pub}")
        return 0

    if args.cmd == "sign":
        policy_bytes = Path(args.policy).read_bytes()
        key = Path(args.key).read_text(encoding="utf-8").strip()
        sig_obj = sign(policy_bytes, key, args.algo)
        out = Path(args.out or (args.policy + ".sig"))
        out.write_text(json.dumps(sig_obj, indent=2), encoding="utf-8")
        print(f"signed -> {out}  (algo={sig_obj['algo']} key_id={sig_obj['key_id']})")
        return 0

    if args.cmd == "verify":
        policy_bytes = Path(args.policy).read_bytes()
        ok, reason = verify_file(policy_bytes, args.sig, args.pub.strip(), args.algo)
        print(f"{'VALID' if ok else 'INVALID'}: {reason}")
        return 0 if ok else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
