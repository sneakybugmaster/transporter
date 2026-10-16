#!/usr/bin/env bash
# Runs the NAT traversal lab (lab.sh) in a privileged container built from
# the integration-test images, which test/integration/run.sh builds:
# transporter:it (agent, iproute2, iptables) and transporter-coordinator:it.
#
#   test/integration/nat/run.sh
set -euo pipefail

cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cid=$(docker create transporter-coordinator:it)
docker cp "$cid:/usr/local/bin/transporter-coordinator" "$tmp/transporter-coordinator" >/dev/null
docker rm "$cid" >/dev/null

docker run --rm --privileged \
  -v "$tmp/transporter-coordinator:/usr/local/bin/transporter-coordinator:ro" \
  -v "$PWD/lab.sh:/lab.sh:ro" \
  --entrypoint /bin/sh transporter:it /lab.sh
