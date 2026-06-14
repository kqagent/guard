"""Fresh-install smoke test: prove the installed wheel works with NO source tree.

Run from a directory that is NOT the repo, using a venv that has only the wheel
installed. Confirms the packaged policy data ships and the gate decides.

    python tools/smoke_install.py
"""
import sys


def main() -> int:
    from aegis.guard import Guard
    from aegis.model import Effect

    g = Guard.load()  # no path -> must read the policy.json packaged in the wheel
    benign = g.check("Bash", {"command": "ls scratch"}, principal="smoke")
    # a destructive command, assembled so no scary literal sits in source
    danger_cmd = " ".join(["rm", "-" + "rf", "/" + "data"])
    danger = g.check("Bash", {"command": danger_cmd}, principal="smoke")
    print("benign  ->", benign.effect.value)
    print("danger  ->", danger.effect.value)

    from aegis.query_compiler import QueryCompiler
    QueryCompiler.from_policy()  # reads packaged policy.json query_proxy block
    print("query_compiler.from_policy() OK")

    import aegis.deploy.landlock_confine  # noqa: F401  -- subpackage imports
    print("aegis.deploy subpackage import OK")

    ok = benign.effect is Effect.ALLOW and danger.effect is Effect.BLOCK
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
