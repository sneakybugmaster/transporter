#!/usr/bin/env bash
# End-to-end UI test (Phase 3 exit criterion): start a fresh coordinator
# container, complete setup and create an auth key in the browser, start an
# agent container with that key, and watch it appear online in the UI.
#
# Needs the transporter:it and transporter-coordinator:it images (built by
# test/integration/run.sh or `docker compose -f test/integration/docker-compose.yml build`)
# and Playwright's Chromium (`pnpm -C web exec playwright install chromium`).
set -euo pipefail

cd "$(dirname "$0")/../.."
net=tp-e2e
port=${E2E_PORT:-18080}
code=E2E0-SETU-PCOD-E000

cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then
    echo "--- e2e failed; container logs follow ---"
    docker logs --tail 80 tp-e2e-coord 2>&1 || true
    docker logs --tail 80 tp-e2e-agent 2>&1 || true
  fi
  docker rm -f tp-e2e-coord tp-e2e-agent >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  exit $status
}
trap cleanup EXIT

docker rm -f tp-e2e-coord tp-e2e-agent >/dev/null 2>&1 || true
docker network rm "$net" >/dev/null 2>&1 || true
docker network create "$net" >/dev/null
docker run -d --name tp-e2e-coord --network "$net" -p "127.0.0.1:$port:8080" \
  -e TRANSPORTER_SETUP_CODE="$code" transporter-coordinator:it >/dev/null

for i in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1 && break
  sleep 1
done

export E2E_BASE_URL="http://127.0.0.1:$port"
export E2E_SETUP_CODE="$code"
export E2E_PUBLIC_URL="http://tp-e2e-coord:8080"
# shellcheck disable=SC2016 # expanded by the test, which exports AUTHKEY
export E2E_AGENT_CMD='docker run --rm --name tp-e2e-agent --network tp-e2e --hostname e2e-agent \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -e TRANSPORTER_COORDINATOR="$COORDINATOR" -e TRANSPORTER_AUTHKEY="$AUTHKEY" \
  transporter:it up'
export E2E_AGENT_STOP="docker rm -f tp-e2e-agent >/dev/null 2>&1 || true"

pnpm -C web e2e
