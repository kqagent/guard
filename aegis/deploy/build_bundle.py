"""Build a signed, deploy-ready Aegis policy bundle.

Produces the directory that gets mounted read-only at /etc/aegis in the
container/Pod:

    bundle/
      policy.json        the policy (copied from aegis/policy.json by default)
      policy.json.sig    detached signature (Ed25519, or HMAC fallback)
      pubkey.hex         the PINNED public key the PDP verifies against

The control function runs this; the PRIVATE key never enters the bundle and
must be stored separately (HSM/KMS in production). The PDP is started with
--pubkey pubkey.hex so it rejects any policy that isn't signed by the
matching private key — that is what makes the guardrails unforgeable by the
agent (the agent only ever gets read-only access to this directory).

    python aegis/deploy/build_bundle.py ./bundle                  # fresh keypair
    python aegis/deploy/build_bundle.py ./bundle --private key.hex # reuse a key
    python aegis/deploy/build_bundle.py ./bundle --policy custom-policy.json

Verifies the bundle loads fail-closed-clean before exiting (a bundle that
its own PDP would reject is a build failure, not a deploy-time surprise).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from aegis import signing  # noqa: E402
from aegis.engine import Engine  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("outdir", type=Path)
    ap.add_argument("--policy", type=Path,
                    default=Path(__file__).resolve().parent.parent / "policy.json")
    ap.add_argument("--private", type=Path, default=None,
                    help="private key file (PEM for ed25519, hex secret for hmac) to reuse")
    ap.add_argument("--algo", default=None,
                    help="ed25519 (default when cryptography is present) or hmac-sha256")
    ap.add_argument("--against", type=Path, default=None,
                    help="previously-signed policy.json to gate this build against: a WIDENING "
                         "of the allow-set is refused unless --approve-widening (monotonic confinement)")
    ap.add_argument("--approve-widening", action="store_true",
                    help="explicitly approve a policy update that widens the allow-set")
    args = ap.parse_args()

    # monotonic-confinement gate: an unreviewed WIDENING of the allow-set must not
    # ship. Compare the new policy against the previously-signed one.
    if args.against is not None:
        from aegis.monotonic_confinement import classify_policy_change
        old_p = json.loads(args.against.read_text(encoding="utf-8"))
        new_p = json.loads(args.policy.read_text(encoding="utf-8"))
        res = classify_policy_change(old_p, new_p)
        if res["verdict"] in ("widening", "fail_closed") and not args.approve_widening:
            print(f"REFUSED — policy update is a {res['verdict']}; newly-allowed: "
                  f"{res.get('newly_allowed') or res.get('reason')}. "
                  "Re-run with --approve-widening after control-function review.")
            return 1
        print(f"  monotonic-confinement: {res['verdict']}"
              + (" (approved)" if res["verdict"] == "widening" else ""))

    algo = args.algo or ("ed25519" if signing.have_ed25519() else "hmac-sha256")
    out = args.outdir
    out.mkdir(parents=True, exist_ok=True)

    # 1. key material
    if args.private:
        priv = args.private.read_text(encoding="utf-8").strip()
        pub = signing.public_from_private(priv, algo)
    else:
        priv, pub = signing.generate_keypair(algo)
        (out / "private.key.KEEP-SECRET").write_text(priv, encoding="utf-8")
        print(f"  generated {algo} keypair; PRIVATE key written to "
              f"{out / 'private.key.KEEP-SECRET'} — move it to an HSM/KMS and delete from disk")

    # 2. policy + detached signature (JSON sig object) + pinned pubkey
    policy_bytes = args.policy.read_bytes()
    (out / "policy.json").write_bytes(policy_bytes)
    sig_obj = signing.sign(policy_bytes, priv, algo)
    (out / "policy.json.sig").write_text(json.dumps(sig_obj), encoding="utf-8")
    (out / "pubkey.hex").write_text(pub, encoding="utf-8")

    # 3. prove the PDP will accept exactly this bundle (fail-closed self-test)
    eng = Engine.load(out / "policy.json", pinned_pubkey=pub,
                      signature_path=out / "policy.json.sig", sig_algo=algo)
    if eng.load_error is not None:
        print(f"FAIL — freshly built bundle does not verify: {eng.load_error}")
        return 1

    # 4. prove a tampered policy is rejected (the whole point)
    tampered = out / "policy.json"
    original = tampered.read_bytes()
    tampered.write_bytes(original.replace(b'"enabled_packs"', b'"enabled_packs_"', 1))
    bad = Engine.load(tampered, pinned_pubkey=pub,
                      signature_path=out / "policy.json.sig", sig_algo=algo)
    tampered.write_bytes(original)  # restore
    if bad.load_error is None:
        print("FAIL — tampered policy was NOT rejected; signing is not protecting the bundle")
        return 1

    print(f"\nPASS — signed bundle ready in {out}/ (algo={algo})")
    print("  files: policy.json, policy.json.sig, pubkey.hex")
    print("  mount this directory read-only at /etc/aegis; start the PDP with")
    print(f"    aegis-pdp --policy /etc/aegis/policy.json --sig /etc/aegis/policy.json.sig --pubkey {pub[:16]}...")
    print("  verified: valid bundle loads clean; tampered policy fails closed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
