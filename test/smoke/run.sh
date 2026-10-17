#!/usr/bin/env bash
# Cross-platform smoke test (Linux, macOS, Windows via Git Bash): a local
# coordinator and agents on one machine must form a mesh.
#
#   test/smoke/run.sh                 # two userspace agents (no privileges)
#   SMOKE_TUN=1 test/smoke/run.sh     # plus a kernel-TUN agent (root/admin)
#   SMOKE_SERVICE=1 test/smoke/run.sh # plus `transporter service install`
#
# BIN (default ./bin) holds transporter and transporter-coordinator. SUDO
# prefixes privileged commands (e.g. SUDO=sudo); leave empty as root/admin.
set -euo pipefail

cd "$(dirname "$0")/../.."
BIN=${BIN:-bin}
SUDO=${SUDO:-}
KEY=trk_smoke-test-auth-key
URL=http://127.0.0.1:18090

case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*) OS=windows EXE=.exe ;;
  Darwin) OS=darwin EXE= ;;
  *) OS=linux EXE= ;;
esac
coord="$BIN/transporter-coordinator$EXE"
tp="$BIN/transporter$EXE"
T=$(mktemp -d)
native() { if [[ $OS == windows ]]; then cygpath -w "$1"; else echo "$1"; fi; }

pids=()
svc_installed=
cleanup() {
  status=$?
  if [[ -n $svc_installed ]]; then $SUDO "${svc_tp:-$tp}" service uninstall || true; fi
  for p in "${pids[@]}"; do $SUDO kill "$p" 2>/dev/null || kill "$p" 2>/dev/null || true; done
  if [[ $status -ne 0 ]]; then
    echo "--- smoke test failed; logs follow ---"
    for f in "$T"/*.log; do echo "## $f"; tail -n 40 "$f"; done
  fi
  exit $status
}
trap cleanup EXIT

log() { echo "== $*"; }

# wait_online <state-dir> <peer> [sudo]: the node at state-dir sees peer online.
wait_online() {
  local dir=$1 peer=$2 run=${3:-} deadline=$((SECONDS + 90))
  until $run "$tp" status --state-dir "$(native "$dir")" 2>/dev/null | grep -Eq "^$peer +[^ ]+ +online"; do
    if ((SECONDS > deadline)); then
      echo "$dir never saw $peer online"
      $run "$tp" status --state-dir "$(native "$dir")" || true
      return 1
    fi
    sleep 1
  done
  echo "$(basename "$dir") sees $peer online"
}

mesh_ip() { ${2:-} "$tp" status --state-dir "$(native "$1")" | head -n 1 | awk '{print $2}' | cut -d/ -f1; }

log "$OS: starting coordinator"
"$coord" -listen 127.0.0.1:18090 -stun-listen 127.0.0.1:13478 -data-dir "$(native "$T/coord")" \
  -bootstrap-authkey "$KEY" >"$T/coord.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 30); do curl -fsS "$URL/healthz" >/dev/null 2>&1 && break; sleep 1; done

log "starting two userspace agents"
"$tp" up --coordinator "$URL" --authkey "$KEY" --userspace --hostname smoke-a \
  --state-dir "$(native "$T/a")" --listen-port 41701 --socks5 127.0.0.1:11081 >"$T/a.log" 2>&1 &
pids+=($!)
"$tp" up --coordinator "$URL" --authkey "$KEY" --userspace --hostname smoke-b \
  --state-dir "$(native "$T/b")" --listen-port 41702 --socks5 off >"$T/b.log" 2>&1 &
pids+=($!)

wait_online "$T/a" smoke-b
wait_online "$T/b" smoke-a
"$tp" ping --state-dir "$(native "$T/a")" -c 3 smoke-b
"$tp" ping --state-dir "$(native "$T/b")" -c 3 smoke-a

log "SOCKS5 proxy passes non-mesh traffic through"
curl -fsS --socks5-hostname 127.0.0.1:11081 "$URL/healthz"
echo

if [[ -n ${SMOKE_TUN:-} ]]; then
  log "starting a kernel-TUN agent"
  iface=tpsmoke0
  $SUDO "$tp" up --coordinator "$URL" --authkey "$KEY" --hostname smoke-c \
    --state-dir "$(native "$T/c")" --listen-port 41703 --interface "$iface" >"$T/c.log" 2>&1 &
  pids+=($!)
  wait_online "$T/c" smoke-a "$SUDO"
  wait_online "$T/a" smoke-c
  "$tp" ping --state-dir "$(native "$T/a")" -c 3 smoke-c

  a_ip=$(mesh_ip "$T/a")
  c_ip=$(mesh_ip "$T/c" "$SUDO")
  if command -v ping >/dev/null; then
    log "kernel ICMP from the host to userspace node smoke-a ($a_ip)"
    if [[ $OS == windows ]]; then ping -n 3 "$a_ip"; else ping -c 3 "$a_ip"; fi
  fi

  if python3 -c 'pass' 2>/dev/null; then
    log "HTTP to smoke-c ($c_ip) through smoke-a's SOCKS5 proxy, by peer name"
    mkdir -p "$T/www" && echo "hello from smoke-c" >"$T/www/index.html"
    (cd "$T/www" && python3 -m http.server --bind "$c_ip" 18888 >"$T/http.log" 2>&1) &
    pids+=($!)
    for _ in $(seq 1 20); do
      out=$(curl -fsS --max-time 5 --socks5-hostname 127.0.0.1:11081 http://smoke-c:18888/ 2>/dev/null) && break
      sleep 1
    done
    [[ ${out:-} == "hello from smoke-c" ]] || { echo "unexpected HTTP response: ${out:-<none>}"; exit 1; }
    echo "$out"
  fi
fi

if [[ -n ${SMOKE_SERVICE:-} ]]; then
  log "installing the agent as a system service"
  case $OS in
    linux) sdir=/var/lib/transporter-smoke ;;
    darwin) sdir="/Library/Application Support/TransporterSmoke" ;;
    windows) sdir="C:\\ProgramData\\TransporterSmoke" ;;
  esac
  svc_tp=$tp
  if [[ $OS == linux ]]; then
    # systemd's ProtectHome hides the checkout; install like a user would.
    $SUDO install "$tp" /usr/local/bin/transporter-smoke
    svc_tp=/usr/local/bin/transporter-smoke
  fi
  svc_installed=1
  # Userspace mode keeps the service test independent of TUN support.
  $SUDO "$svc_tp" service install --coordinator "$URL" --authkey "$KEY" --userspace --socks5 off \
    --hostname smoke-svc --state-dir "$sdir" --listen-port 41704
  wait_online "$T/a" smoke-svc
  $SUDO "$svc_tp" service uninstall
  svc_installed=
  log "service removed"
fi

echo PASS
