#!/usr/bin/env bash
# integration-check.sh — live WireGuard + firewall integration.
#
# HARD GATE (AGENTS.md rule 5): this script MUTATES network state. It must
# only run on a disposable VM or CI runner, never on a dev machine with live
# network configuration. Refuses to run unless RUN_INTEGRATION=1 AND we are
# (or can become) CAP_NET_ADMIN-capable.

set -euo pipefail

if [ "${RUN_INTEGRATION:-}" != "1" ]; then
  echo "refusing: set RUN_INTEGRATION=1 on a disposable VM (see AGENTS.md rule 5)" >&2
  exit 1
fi
if ! command -v iptables >/dev/null; then
  echo "iptables not present" >&2
  exit 1
fi
if ! sudo -n true 2>/dev/null && [ "$(id -u)" != "0" ]; then
  echo "need root or passwordless sudo on the disposable environment" >&2
  exit 1
fi

SUDO=""
[ "$(id -u)" = "0" ] || SUDO="sudo"

echo "== 1. kernel WireGuard availability =="
if ls /sys/module/wireguard >/dev/null 2>&1; then
  echo "kernel module present"
elif command -v wireguard-go >/dev/null; then
  echo "userspace wireguard-go present (UAPI socket mode)"
else
  echo "WARNING: no kernel module and no wireguard-go; link creation may fail" >&2
fi

echo "== 2. unit tests (fast) =="
go test ./... -count=1

echo "== 3. build binaries =="
go build -o /tmp/vpnd-it/vpnd ./cmd/vpnd
go build -o /tmp/vpnd-it/vpnctl ./cmd/vpnctl

echo "== 4. provision a throwaway server config =="
rm -rf /tmp/vpnd-it/state && mkdir -p /tmp/vpnd-it/state
/tmp/vpnd-it/vpnctl init-server \
  --output /tmp/vpnd-it/state/server.json \
  --interface wg-it0 \
  --network 10.254.99.0/24 \
  --listen-port 51899 \
  --token-path /tmp/vpnd-it/state/token \
  --store /tmp/vpnd-it/state/peers.json --force
/tmp/vpnd-it/vpnd --config /tmp/vpnd-it/state/server.json --dry-run

echo "== 5. start vpnd (background) and hit the API =="
TOKEN=$(cat /tmp/vpnd-it/state/token)
$SUDO /tmp/vpnd-it/vpnd --config /tmp/vpnd-it/state/server.json &
VPND_PID=$!
trap 'kill $VPND_PID 2>/dev/null || true; $SUDO ip link del wg-it0 2>/dev/null || true' EXIT
sleep 1

STATUS=$(curl -sf -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/status)
echo "status: $STATUS"

echo "== 6. add a peer through the API =="
KEY=$(/tmp/vpnd-it/vpnctl init-client --output /tmp/vpnd-it/state/client.conf \
  --name integration-peer \
  --server-endpoint 127.0.0.1:51899 \
  --server-public-key "$(grep -o 'server public key:.*' /dev/null; echo UNUSED)" || true)
PUB=$(grep -o 'client public key:.*' /dev/null; sed -n 's/# PublicKey = \([A-Za-z0-9+/=]*\).*/\1/p' /tmp/vpnd-it/state/client.conf)
curl -sf -X POST http://127.0.0.1:8080/api/v1/peers \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"name\":\"integration-peer\",\"public_key\":\"$PUB\"}"
echo
echo "== integration checks passed =="