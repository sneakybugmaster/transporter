#!/usr/bin/env bash
# End-to-end test: start a coordinator and three agents, then check that every
# agent reaches every other one through the mesh, before and after a restart.
#
#   test/integration/run.sh            # build images and run
#   SKIP_BUILD=1 test/integration/run.sh   # use already built transporter:it images
#   KEEP=1 test/integration/run.sh         # leave the containers running afterwards
set -euo pipefail

cd "$(dirname "$0")"
compose=(docker compose -f docker-compose.yml)
nodes=(alpha bravo charlie)

cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then
    echo "--- test failed; logs follow ---"
    "${compose[@]}" logs --no-color --tail=200 || true
  fi
  if [[ -z "${KEEP:-}" ]]; then
    "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  exit $status
}
trap cleanup EXIT

if [[ -z "${SKIP_BUILD:-}" ]]; then
  "${compose[@]}" build
fi
"${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${compose[@]}" up -d

# wait_mesh waits until every agent sees both other agents online with a
# completed WireGuard handshake.
wait_mesh() {
  local deadline=$((SECONDS + 90))
  for n in "${nodes[@]}"; do
    until "${compose[@]}" exec -T "$n" transporter status --json 2>/dev/null |
      python3 -c '
import json, sys
st = json.load(sys.stdin)
peers = st["engine"]["peers"]
sys.exit(0 if len(peers) == 2 and all(p["online"] for p in peers) else 1)'; do
      if ((SECONDS > deadline)); then
        echo "timed out waiting for $n to see the mesh"
        "${compose[@]}" exec -T "$n" transporter status || true
        return 1
      fi
      sleep 1
    done
    echo "$n sees all peers online"
  done
}

mesh_ip() {
  "${compose[@]}" exec -T "$1" transporter status --json |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["engine"]["addresses"][0].split("/")[0])'
}

check_pairs() {
  for src in "${nodes[@]}"; do
    for dst in "${nodes[@]}"; do
      [[ $src == "$dst" ]] && continue
      local ip
      ip=$(mesh_ip "$dst")
      echo "== $src -> $dst ($ip)"
      # Built-in echo over the mesh, resolved by peer name.
      "${compose[@]}" exec -T "$src" transporter ping -c 3 "$dst"
      # Kernel ICMP through the TUN interface proves real routing.
      "${compose[@]}" exec -T "$src" ping -c 2 -W 2 "$ip"
    done
  done
}

wait_mesh
"${compose[@]}" exec -T alpha transporter status
check_pairs

bravo_ip=$(mesh_ip bravo)
echo "== restarting bravo: it must keep its identity and address"
"${compose[@]}" restart bravo
wait_mesh
if [[ $(mesh_ip bravo) != "$bravo_ip" ]]; then
  echo "bravo changed address from $bravo_ip to $(mesh_ip bravo)"
  exit 1
fi
check_pairs

echo "== nodes known to the coordinator"
"${compose[@]}" exec -T coordinator /usr/local/bin/transporter-coordinator nodes list --data-dir /data

echo "PASS"
