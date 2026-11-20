# Runbook

## Requirements (host)

- Linux, kernel ≥ 5.6 (in-tree WireGuard) or `wireguard` module installed
- `ip`, `iptables` present; `wg` optional (vpnd does not shell out to it)
- `CAP_NET_ADMIN` for the vpnd process (root or `setcap cap_net_admin+ep vpnd`)
- One UDP port open (default 51820) — WireGuard is silent to unauthenticated probes

## Provision a server (quick path)

```bash
# 1. generate a server config with fresh keys and an admin token
./vpnctl init-server --output /etc/vpnd/server.json --network 10.100.0.0/24

# 2. review what will be applied (no changes yet)
vpnd --config /etc/vpnd/server.json --dry-run

# 3. run
vpnd --config /etc/vpnd/server.json
# or: systemctl enable --now vpnd
```

`--dry-run` prints the rendered iptables ruleset and the interface parameters and
exits — it performs **zero** live mutations.

## Add a client

```bash
# on the client machine (generates private key locally; private key never leaves)
vpnctl init-client --name laptop --output /etc/wireguard/laptop.conf

# register the peer on the server (vpnctl prints the POST for you):
curl -s -X POST http://127.0.0.1:8080/api/v1/peers \
  -H "Authorization: Bearer $VPND_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"laptop","public_key":"<client public key>"}'

# bring the client up
wg-quick up /etc/wireguard/laptop.conf
```

## Operations

| Task | Command |
| --- | --- |
| status | `curl -H "Authorization: Bearer $VPND_TOKEN" 127.0.0.1:8080/api/v1/status` |
| list peers | `... /api/v1/peers` |
| remove peer | `DELETE .../api/v1/peers/<id>` |
| reload + reconcile | `kill -HUP $(pidof vpnd)` |
| graceful stop | `systemctl stop vpnd` (SIGTERM) |

## Troubleshooting

| Symptom | Check |
| --- | --- |
| handshake never completes | peer endpoint reachable? server `status` shows peer + allowed ips; client key matches registered public key |
| client has no internet | `sysctl net.ipv4.ip_forward`, rendered FORWARD rule, NAT rule (`vpnd --dry-run` output) |
| "permission denied" on start | missing CAP_NET_ADMIN → `setcap cap_net_admin+ep vpnd` or run as root |
| store locked / torn | store writes are atomic; a leftover `*.tmp` file means a crash mid-write — safe to delete after checking journal |
| API 401 | token file readable by vpnd only (0600), token matches `api.token_path` |

## Remote admin (explicit opt-in)

Do not bind the API to 0.0.0.0. If remote management is required, terminate TLS in
front (nginx/stunnel) with client certificates, and restrict by firewall. v1 ships
loopback-only defaults by design (ADR-004).
