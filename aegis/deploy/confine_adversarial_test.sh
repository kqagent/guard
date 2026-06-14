#!/bin/bash
# Adversarial test for confine_run.sh. Run on Linux (or WSL2):
#   bash aegis/deploy/confine_adversarial_test.sh
#
# Proves TWO things:
#  1. FAIL-CLOSED: if the runner cannot make system dirs read-only it REFUSES to
#     run the payload (exit 3) rather than run half-confined. (On WSL2, where
#     sub-path RO binds are unsupported, this is the default outcome — which is
#     itself the property we want to prove.)
#  2. PLATFORM-INDEPENDENT controls hold (shown via the demo override that skips
#     only the system-dir RO check): network egress is physically impossible
#     (empty netns), host secrets are unreachable (masked), no-new-privs is set,
#     the policy dir is read-only, and /scratch is the only writable path.
#
# On NATIVE Linux the default path (strategy A: bind + remount-ro of
# /usr,/bin,/lib — the same mechanism bubblewrap and OpenAI Codex use) makes the
# system dirs genuinely read-only and the fail-closed check passes silently;
# all controls then hold without the override.
set -u
# Skip cleanly (not fail) where unprivileged user namespaces are unavailable —
# we're testing the confinement CODE, not the runner's kernel policy.
if ! unshare --user --map-root-user true 2>/dev/null; then
  echo "skip: unprivileged user namespaces unavailable on this host"; exit 0
fi
HERE="$(cd "$(dirname "$0")" && pwd)"
POLICY="$(cd "$HERE/.." && pwd)"      # the aegis/ package dir (has policy*.json)
# Normalize to an LF copy so this works on a Windows checkout (CRLF) too; the
# runner re-execs $0, which must be LF for bash.
RUN="$(mktemp)"
tr -d '\r' < "$HERE/confine_run.sh" > "$RUN"
chmod +x "$RUN" 2>/dev/null || true
pass=0; fail=0
ok(){ echo "  PASS  $1"; pass=$((pass+1)); }
no(){ echo "  FAIL  $1 -- $2"; fail=$((fail+1)); }
run(){ AEGIS_DEMO_SKIP_ROCHECK=1 bash "$RUN" "$POLICY" -- /bin/bash -c "$1" 2>&1; }

echo "=== confinement: fail-closed property (default) ==="
out="$(bash "$RUN" "$POLICY" -- /bin/bash -c 'echo PAYLOAD_RAN' 2>&1)"; rc=$?
if echo "$out" | grep -q PAYLOAD_RAN; then
  # native Linux with RO enforced: payload runs AND the run was fully confined.
  ok "system dirs read-only on this platform; payload ran fully confined (rc=$rc)"
else
  echo "$out" | grep -q 'failing closed' \
    && ok "fail-closed: refused to run when RO unenforceable (rc=$rc) [expected on WSL2]" \
    || no "fail-closed behaviour" "$out"
fi

echo
echo "=== platform-independent controls ==="
out="$(run 'echo confined-ok; echo strategy=$AEGIS_CONFINEMENT')"
echo "$out" | grep -q confined-ok && ok "sandbox runs ($(echo "$out" | grep -o 'strategy=[^ ]*'))" \
  || { no "baseline" "$out"; echo "RESULT: $pass passed, $((fail+1)) failed"; exit 1; }
out="$(run 'cat /proc/self/status 2>/dev/null | grep NoNewPrivs')"
echo "$out" | grep -q 'NoNewPrivs:.*1' && ok "no-new-privileges set" || no "nnp" "$out"
out="$(run 'cat /home/*/* /host/home/*/* 2>/dev/null; ls -A /home 2>/dev/null; echo END')"
echo "$out" | grep -qiE 'BEGIN|PRIVATE KEY|[A-Za-z0-9+/]{64}' && no "host secrets masked" "leaked" \
  || ok "host secrets unreachable (masked/absent in sandbox view)"
out="$(run 'python3 -c "import socket;socket.setdefaulttimeout(4);socket.create_connection((chr(0x31)+\".1.1.1\",53))" 2>&1; echo rc=$?')"
echo "$out" | grep -q 'rc=0' && no "egress impossible" "connected" \
  || ok "network egress impossible (isolated empty netns)"
out="$(run 'echo hi > /scratch/n.txt && cat /scratch/n.txt')"
echo "$out" | grep -q hi && ok "scratch writable (work proceeds)" || no "scratch" "$out"
out="$(run 'for p in /policy/policy.json /policy/policy.kdb.json; do echo x > $p 2>/dev/null && echo WROTE; done; echo END')"
echo "$out" | grep -q WROTE && no "policy read-only" "wrote policy" \
  || ok "policy dir read-only (agent cannot edit its own guardrails)"

echo
echo "RESULT: $pass passed, $fail failed"
exit $fail
