#!/usr/bin/env bash
# Subnet routes, exit nodes, MagicDNS, split DNS and access-control policy,
# end to end in Docker. See docker-compose.yml for the topology.
#
#   test/integration/routing/run.sh            # build images and run
#   SKIP_BUILD=1 test/integration/routing/run.sh
#   KEEP=1 test/integration/routing/run.sh     # leave the containers running
set -euo pipefail

cd "$(dirname "$0")"
compose=(docker compose -f docker-compose.yml)
export COOKIES=$(mktemp)

cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then
    echo "--- test failed; logs follow ---"
    "${compose[@]}" logs --no-color --tail=150 || true
  fi
  if [[ -z "${KEEP:-}" ]]; then
    "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -f "$COOKIES"
  exit $status
}
trap cleanup EXIT

api() { python3 api.py "$@"; }
x() { "${compose[@]}" exec -T "$@"; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
fail() { echo "FAIL: $*"; exit 1; }

# retry <seconds> <command...>: until it succeeds.
retry() {
  local deadline=$((SECONDS + $1)); shift
  until "$@"; do
    ((SECONDS > deadline)) && return 1
    sleep 1
  done
}

# fails <command...>: the command must not succeed.
fails() { if "$@" >/dev/null 2>&1; then fail "unexpectedly succeeded: $*"; fi; }

if [[ -z "${SKIP_BUILD:-}" ]]; then
  "${compose[@]}" build
fi
"${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${compose[@]}" up -d

echo "== admin setup"
retry 30 api GET /setup >/dev/null
api POST /setup '{"setupCode":"ROUT-INGT-ESTC-ODE1","username":"admin","password":"integration-pass"}' >/dev/null

node_id() { api GET /nodes | json "[n['id'] for n in d if n['name']=='$1'][0]"; }
peer_online() { x "$1" transporter status --json | json "any(p['name']=='$2' and p['online'] for p in d['engine']['peers'])" | grep -q True; }
for pair in "alpha gw" "alpha bravo" "bravo gw"; do
  set -- $pair
  retry 60 peer_online "$1" "$2" || fail "$1 never saw $2"
done
echo "mesh is up"

gw=$(node_id gw); alpha=$(node_id alpha); bravo=$(node_id bravo)
adv=$(api GET /nodes/"$gw" | json "d['advertisedRoutes']")
[[ $adv == "['0.0.0.0/0', '10.0.1.0/24']" ]] || fail "gw advertises $adv"

echo "== unapproved routes are not used"
fails x alpha wget -q -T 3 -O - http://10.0.1.10:8000/

echo "== approve the subnet route and the exit node"
api PATCH /nodes/"$gw" '{"approvedRoutes":["10.0.1.0/24","0.0.0.0/0"]}' >/dev/null

echo "== subnet route: alpha reaches the LAN host, masqueraded behind gw"
lan_from() { x alpha wget -q -T 3 -O - http://10.0.1.10:8000/; }
retry 30 lan_from >/dev/null || fail "alpha cannot reach 10.0.1.10 through gw"
[[ $(lan_from) == 10.0.1.2 ]] || fail "LAN host saw $(lan_from), want gw's LAN address"
echo "bravo does not accept routes, so it has none"
fails x bravo wget -q -T 3 -O - http://10.0.1.10:8000/

echo "== exit node: alpha reaches the 'internet' through gw"
wan_from() { x alpha wget -q -T 3 -O - http://10.0.2.10:8000/; }
retry 30 wan_from >/dev/null || fail "alpha cannot reach 10.0.2.10 through the exit node"
[[ $(wan_from) == 10.0.2.2 ]] || fail "WAN host saw $(wan_from), want gw's WAN address"
echo "the control plane stays outside the tunnel"
retry 10 peer_online alpha bravo || fail "alpha lost the coordinator while using the exit node"
x alpha transporter ping -c 2 bravo

echo "== MagicDNS"
bravo_ip=$(x bravo transporter status --json | json "d['engine']['addresses'][0].split('/')[0]")
x alpha nslookup bravo.mesh.internal 100.100.100.100 | grep -q "$bravo_ip" || fail "bravo.mesh.internal did not resolve"
fails x alpha nslookup nobody.mesh.internal 100.100.100.100

echo "== split DNS through the subnet router"
api PUT /dns '{"magicDNS":true,"domain":"mesh.internal","split":[{"domain":"corp.test","resolvers":["10.0.1.10"]}]}' >/dev/null
split_ok() { x alpha nslookup app.corp.test 100.100.100.100 2>/dev/null | grep -q 10.0.1.10; }
retry 30 split_ok || fail "app.corp.test did not resolve through the split DNS resolver"

echo "== access-control policy"
api PATCH /nodes/"$alpha" '{"tags":["tag:dev"]}' >/dev/null
api PATCH /nodes/"$bravo" '{"tags":["tag:web"]}' >/dev/null
api PUT /policy '{"policy":"{\"acls\":[{\"action\":\"accept\",\"src\":[\"tag:dev\"],\"dst\":[\"tag:web:*\",\"10.0.1.0/24:8000\"]}],\"tests\":[{\"src\":\"alpha\",\"accept\":[\"bravo:22\"],\"deny\":[\"10.0.1.10:22\"]}]}"}' >/dev/null
alpha_ip=$(x alpha transporter status --json | json "d['engine']['addresses'][0].split('/')[0]")
# alpha may reach bravo (any port) and the LAN host on port 8000 only.
retry 15 bash -c "! $(printf '%q ' "${compose[@]}") exec -T bravo transporter ping -c 1 -timeout 1s alpha >/dev/null 2>&1" ||
  fail "bravo can still reach alpha"
x alpha transporter ping -c 2 bravo
x alpha ping -c 2 -W 2 "$bravo_ip"
lan_from >/dev/null || fail "alpha lost the LAN host on an allowed port"
fails x alpha wget -q -T 3 -O - http://10.0.2.10:8000/   # the exit route is not allowed
fails x alpha nslookup app.corp.test 100.100.100.100     # neither is DNS on the LAN host
echo "bravo answers alpha's pings (stateful) but cannot open connections to alpha"
fails x bravo ping -c 1 -W 2 "$alpha_ip"
echo "gw has no rule with bravo, so they no longer see each other"
retry 15 bash -c "! $(printf '%q ' "${compose[@]}") exec -T bravo transporter status --json | grep -q '\"name\": \"gw\"'" ||
  fail "bravo still sees gw"

res=$(api POST /policy/check '{"src":"bravo","dst":"alpha","port":22}' | json "d['allowed']")
[[ $res == False ]] || fail "policy check says bravo -> alpha:22 is allowed"

echo "== topology and audit log"
links() { api GET /topology | json "len(d['links'])"; }
retry 60 bash -c "[[ \$(python3 api.py GET /topology | python3 -c 'import json,sys; print(len(json.load(sys.stdin)[\"links\"]))') -ge 2 ]]" ||
  fail "no topology reported"
api GET /audit | json "[e['action'] for e in d]" | grep -q policy.update || fail "policy change not audited"

echo "PASS"
