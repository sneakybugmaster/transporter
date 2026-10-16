#!/bin/sh
# NAT traversal lab. Runs inside one privileged container (see run.sh) and
# builds this topology out of network namespaces:
#
#                      inet (bridge 10.99.0.0/24)
#        ┌──────────────┬──────────┼──────────┬──────────────┐
#   coord .10      nat-a .11   nat-b .12   nat-c .13      nat-d .14
#                   cone        cone        symmetric      symmetric
#                     │           │           │              │
#                 alpha        bravo       charlie         delta
#               10.10.1.10   10.10.2.10   10.10.3.10     10.10.4.10
#
# Cone routers keep the source port for every destination (endpoint-
# independent mapping, like most home routers); symmetric routers pick a
# random port per destination. alpha and bravo must end up connected
# directly; every pair involving charlie or delta must use the relay.
set -eu

KEY=trk_integration-test-key
NODES="alpha bravo charlie delta"
pids=""

log() { echo "== $*"; }

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "--- lab failed; status and logs follow ---"
    for n in $NODES; do
      echo "## $n"
      ip netns exec "node-$n" transporter status --state-dir "/tmp/$n" 2>/dev/null || true
      tail -n 40 "/tmp/$n.log" 2>/dev/null || true
    done
    tail -n 40 /tmp/coordinator.log 2>/dev/null || true
  fi
  for p in $pids; do kill "$p" 2>/dev/null || true; done
  exit "$status"
}
trap cleanup EXIT

# --- topology ---------------------------------------------------------------
ip netns add inet
ip -n inet link add br0 type bridge
ip -n inet link set br0 up
ip -n inet link set lo up

attach() { # attach <ns> <ip/len>: connect a namespace to the inet bridge
  ip netns add "$1" 2>/dev/null || true
  ip link add "w-$1" type veth peer name wan netns "$1"
  ip link set "w-$1" netns inet
  ip -n inet link set "w-$1" master br0 up
  ip -n "$1" addr add "$2" dev wan
  ip -n "$1" link set wan up
  ip -n "$1" link set lo up
}

attach coord 10.99.0.10/24

site() { # site <name> <index> <cone|symmetric>
  name=$1 idx=$2 mode=$3
  attach "nat-$name" "10.99.0.1$idx/24"
  ip netns add "node-$name"
  ip link add lan netns "nat-$name" type veth peer name eth0 netns "node-$name"
  ip -n "nat-$name" addr add "10.10.$idx.1/24" dev lan
  ip -n "nat-$name" link set lan up
  ip -n "node-$name" addr add "10.10.$idx.10/24" dev eth0
  ip -n "node-$name" link set eth0 up
  ip -n "node-$name" link set lo up
  ip -n "node-$name" route add default via "10.10.$idx.1"
  ip netns exec "nat-$name" sysctl -qw net.ipv4.ip_forward=1
  # Like real routers, drop unsolicited traffic from the WAN. (Accepting it
  # would let a peer's early probe create a conntrack entry that later
  # forces a different source port: hole punching would then fail for a
  # reason no real router has.)
  ip netns exec "nat-$name" iptables -A INPUT -i wan -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip netns exec "nat-$name" iptables -A INPUT -i wan -j DROP
  if [ "$mode" = symmetric ]; then
    ip netns exec "nat-$name" iptables -t nat -A POSTROUTING -o wan -j MASQUERADE --random
  else
    ip netns exec "nat-$name" iptables -t nat -A POSTROUTING -o wan -j MASQUERADE
  fi
}
site alpha 1 cone
site bravo 2 cone
site charlie 3 symmetric
site delta 4 symmetric

# Sanity check: LANs are only reachable through the mesh.
if ip netns exec node-alpha ping -c 1 -W 1 10.10.2.10 >/dev/null 2>&1; then
  echo "alpha reaches bravo's LAN directly: topology is broken"
  exit 1
fi

# --- processes --------------------------------------------------------------
ip netns exec coord transporter-coordinator -data-dir /tmp/coord \
  -bootstrap-authkey "$KEY" -log-level debug >/tmp/coordinator.log 2>&1 &
pids="$pids $!"
for i in $(seq 1 30); do
  ip netns exec coord transporter-coordinator -healthcheck 2>/dev/null && break
  sleep 0.5
done

for n in $NODES; do
  ip netns exec "node-$n" transporter up --coordinator http://10.99.0.10:8080 \
    --authkey "$KEY" --hostname "$n" --state-dir "/tmp/$n" --log-level debug >"/tmp/$n.log" 2>&1 &
  pids="$pids $!"
done

status_of() { ip netns exec "node-$1" transporter status --state-dir "/tmp/$1" 2>/dev/null; }

# path_of <node> <peer>: "direct", "relay" or "-" (the PATH column).
path_of() { status_of "$1" | awk -v p="$2" '$1 == p { print $4 }'; }

expected_path() {
  case "$1-$2" in
    alpha-bravo | bravo-alpha) echo direct ;;
    *) echo relay ;;
  esac
}

# --- checks -----------------------------------------------------------------
log "every pair must be reachable"
for src in $NODES; do
  for dst in $NODES; do
    [ "$src" = "$dst" ] && continue
    deadline=$(($(date +%s) + 90))
    until ip netns exec "node-$src" transporter ping --state-dir "/tmp/$src" -c 1 -timeout 1s "$dst" >/dev/null 2>&1; do
      if [ "$(date +%s)" -gt "$deadline" ]; then
        echo "$src cannot reach $dst"
        exit 1
      fi
      sleep 1
    done
    echo "$src -> $dst reachable"
  done
done

log "paths must match what the NAT types allow"
for src in $NODES; do
  for dst in $NODES; do
    [ "$src" = "$dst" ] && continue
    want=$(expected_path "$src" "$dst")
    deadline=$(($(date +%s) + 60))
    while :; do
      got=$(path_of "$src" "$dst")
      [ "$got" = "$want" ] && break
      if [ "$(date +%s)" -gt "$deadline" ]; then
        echo "$src -> $dst uses path '$got', want '$want'"
        exit 1
      fi
      sleep 1
    done
    echo "$src -> $dst: $got"
  done
done

for n in $NODES; do
  log "$n"
  status_of "$n"
done

log "kernel ICMP over a direct and a relayed path"
ip netns exec node-alpha ping -c 3 -W 2 "$(status_of bravo | awk 'NR == 1 { split($2, a, "/"); print a[1] }')"
ip netns exec node-charlie ping -c 3 -W 2 "$(status_of delta | awk 'NR == 1 { split($2, a, "/"); print a[1] }')"

echo PASS
