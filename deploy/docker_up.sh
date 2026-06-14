#!/usr/bin/env bash
# Bring up the Aegis enforcement plane in containers — one command.
#
#   deploy/docker_up.sh          # build signed bundle, build images, up, healthcheck
#   deploy/docker_up.sh down     # tear the stack down
#
# Prereqs: docker + the compose plugin, and python3 (to build the signed
# bundle once, on the host, before it is mounted read-only into the PDP).
# The bundle's PRIVATE key stays on the host and is never copied into an image.
set -euo pipefail
cd "$(dirname "$0")/.."          # repo root

COMPOSE="aegis/deploy/docker-compose.yml"
BUNDLE="aegis/deploy/bundle"     # compose mounts ./bundle relative to the compose file

if [ "${1:-}" = "down" ]; then
  docker compose -f "$COMPOSE" down
  exit 0
fi

echo "== Building signed policy bundle (host-side) =="
if command -v python3 >/dev/null; then PY=python3; else PY=python; fi
"$PY" aegis/deploy/build_bundle.py "$BUNDLE"
echo "   bundle -> $BUNDLE (mounted read-only into the PDP)"

echo "== Building images and starting the stack =="
docker compose -f "$COMPOSE" up -d --build

echo "== Waiting for the PDP to report healthy =="
ok=false
for _ in $(seq 1 40); do
  if docker compose -f "$COMPOSE" exec -T aegis-pdp \
       python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8787/healthz',timeout=2)" \
       >/dev/null 2>&1; then ok=true; break; fi
  sleep 0.5
done
if [ "$ok" = true ]; then
  echo "   PDP healthy."
else
  echo "   PDP health check timed out; recent logs:" >&2
  docker compose -f "$COMPOSE" logs --tail 30 aegis-pdp >&2 || true
  exit 1
fi

cat <<EOF

Aegis enforcement plane is up (containers):
  aegis-pdp      policy decision point   (signed bundle mounted read-only)
  aegis-egress   egress forward proxy    (host allowlist + SSRF + DLP)
  governed-agent locked-down workload    (read-only rootfs, non-root, no direct egress)

  Logs:   docker compose -f $COMPOSE logs -f
  Verify: python tools/verify_deployment.py aegis/deploy/k8s.yaml   (12/12 controls)
  Down:   deploy/docker_up.sh down
EOF
