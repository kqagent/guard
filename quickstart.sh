#!/usr/bin/env bash
# Aegis quickstart — zero to a running, self-proven policy gate in one command.
#
#   ./quickstart.sh            # venv + install + sign bundle + acceptance suite + live PDP demo
#   ./quickstart.sh --no-pdp   # skip starting the background PDP (suite only)
#   ./quickstart.sh --docker   # hand off to the container path instead
#
# Designed for a client evaluating Aegis on a fresh Linux box: it needs only
# python3 (>=3.10). Everything else is built here. The script ends by PROVING
# the gate works — a benign action allowed, a destructive one blocked — so a
# successful run is also a demo.
set -euo pipefail
cd "$(dirname "$0")"

GREEN=$'\e[32m'; RED=$'\e[31m'; BOLD=$'\e[1m'; NC=$'\e[0m'
say(){ echo "${BOLD}== $* ==${NC}"; }
ok(){ echo "${GREEN}OK${NC} $*"; }
die(){ echo "${RED}FAIL${NC} $*" >&2; exit 1; }

if [ "${1:-}" = "--docker" ]; then
  exec bash deploy/docker_up.sh
fi
NO_PDP=false; [ "${1:-}" = "--no-pdp" ] && NO_PDP=true

say "1/6  Checking prerequisites"
command -v python3 >/dev/null || die "python3 not found (need >=3.10)"
PYV=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')
python3 -c 'import sys;sys.exit(0 if sys.version_info[:2]>=(3,10) else 1)' \
  || die "python3 $PYV too old; need >=3.10"
ok "python3 $PYV"

say "2/6  Creating venv and installing Aegis"
python3 -m venv .venv
# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install -q --upgrade pip
python -m pip install -q -e ".[signing]"
ok "installed aegis-guardrails (+signing)"

say "3/6  Building a signed policy bundle"
python aegis/deploy/build_bundle.py ./bundle >/tmp/aegis_bundle.log 2>&1 \
  && ok "signed bundle in ./bundle (policy.json + .sig + pinned pubkey)" \
  || { cat /tmp/aegis_bundle.log; die "bundle build failed"; }

say "4/6  Running the acceptance suite (the proof it works)"
python -m aegis.run_all_checks || die "acceptance suite failed — do not deploy"
ok "all core checks passed"

if [ "$NO_PDP" = true ]; then
  say "Done (--no-pdp)"; exit 0
fi

say "5/6  Starting the out-of-process PDP (signed bundle, fail-closed)"
PUB=$(cat bundle/pubkey.hex)
mkdir -p .aegis
python -m aegis.pdp_service --policy bundle/policy.json --sig bundle/policy.json.sig \
  --pubkey "$PUB" --audit .aegis/audit.jsonl --host 127.0.0.1 --port 8787 \
  >/tmp/aegis_pdp.log 2>&1 &
PDP_PID=$!
trap 'kill $PDP_PID 2>/dev/null || true' EXIT
for i in $(seq 1 20); do
  if curl -fsS http://127.0.0.1:8787/healthz >/dev/null 2>&1; then break; fi
  sleep 0.25
done
curl -fsS http://127.0.0.1:8787/healthz >/dev/null 2>&1 \
  && ok "PDP healthy on http://127.0.0.1:8787" \
  || { cat /tmp/aegis_pdp.log; die "PDP did not come up"; }

say "6/6  Proving the gate decides (live, through the running PDP)"
python tools/prove_gate.py http://127.0.0.1:8787 || die "gate proof failed"
ok "gate is live and deciding"

cat <<EOF

${GREEN}${BOLD}Aegis is up.${NC}
  PDP:        http://127.0.0.1:8787  (pid $PDP_PID; audit -> .aegis/audit.jsonl)
  Policy:     bundle/policy.json  (signed; edit aegis/policy.json + re-run build_bundle.py to change)
  Integrate:  from aegis.guard import Guard;  Guard.remote("http://127.0.0.1:8787")
  Next:       see DEPLOY.md (containers, hardening, kdb+ pilot) and PILOT.md (monitor->enforce)

The PDP stops when this script exits. To run it persistently, use:
  deploy/docker_up.sh   (containers)   or the systemd unit in DEPLOY.md
EOF
