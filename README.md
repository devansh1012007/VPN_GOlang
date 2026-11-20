# VPN_GOlang — a WireGuard VPN platform in Go

A complete, maintainable, secure VPN platform built in Go on top of
[WireGuard](https://www.wireguard.com/): a server daemon (`vpnd`) that manages
the interface, peers, firewall and routing, plus an operator CLI (`vpnctl`)
and a token-authenticated REST admin API.

> **Crypto policy:** the platform never implements its own cryptography
> (constraint in `MASTER_PROMPT.md`). All tunnel crypto is WireGuard's; all
> key material is generated/parsed by `golang.zx2c4.com/wireguard/wgctrl`.

## Features

- **Server daemon (`cmd/vpnd`)**
  - WireGuard interface lifecycle via `wgctrl` (generic netlink) — create,
    configure, reconcile peers, teardown.
  - IPAM: automatic per-peer address allocation from the VPN subnet,
    crash-safe (allocations restored from the peer store on restart).
  - Firewall orchestration: idempotent iptables rules (NAT masquerade +
    forward policy), rendered deterministically and removable exactly.
  - Kernel parameter management (`net.ipv4.ip_forward`).
  - Durable JSON peer store with atomic writes (temp+rename, 0600).
  - REST admin API on loopback: status, list/add/get/remove peers —
    constant-time bearer-token authentication.
  - `--dry-run`: print the full plan (rules, link, peers) with zero mutation.
  - Graceful shutdown; SIGHUP reload; structured logging.
- **Operator CLI (`cmd/vpnctl`)**
  - `init-server`: generate a server config with fresh WireGuard keys and
    an admin token.
  - `init-client`: generate a client keypair and a wg-quick-compatible
    client config.
  - `register`: register the peer against the admin API.
  - `show --redact`: display configs with private keys redacted.
- **Engineering**
  - Table-driven unit tests across `internal/` (fakes for wgctrl/iptables —
    no dev-machine network mutation).
  - Gated integration tests (`RUN_INTEGRATION=1`) for disposable VMs.
  - CI workflow (build, vet, test, smoke) + manual integration job.
  - systemd unit and Dockerfile with capability bounds.
  - Architecture, STRIDE threat model, 6 ADRs, runbook (see `docs/`).

## Quick start

```bash
make build test          # build + unit tests
./build/vpnctl init-server --output server.json --token-path token --store peers.json
./build/vpnd --config server.json --dry-run      # plan only, no changes
sudo ./build/vpnd --config server.json           # apply (needs CAP_NET_ADMIN)

# on a client machine:
./build/vpnctl init-client --name laptop --output laptop.conf \
  --server-endpoint <server-ip> --server-public-key <server-pub>
VPND_TOKEN=$(cat token) ./build/vpnctl register --name laptop \
  --public-key <client-pub>            # registers via the API
```

Full operations guide: `docs/runbook.md`.

## Repository layout

```
AGENTS.md            agent collaboration rules (review protocol, hard rules)
MASTER_PROMPT.md     requirements, constraints, workflow
EXECUTION_PLAN.md    phase status + evidence + honest debt ledger
SKILLS_INDEX.md      required reading per phase
cmd/vpnd             server daemon
cmd/vpnctl           operator CLI
internal/config       config load/validate/save (redaction-safe)
internal/wireguard    wgctrl control plane, peer model, key handling
internal/network      IPAM, firewall renderer, sysctl, link manager
internal/store        JSON peer store (atomic writes)
internal/auth         token authn (constant-time)
internal/api          REST API (/api/v1)
internal/server       orchestrator (implements the API backend)
internal/logging      structured logging
internal/integration  gated live tests (RUN_INTEGRATION=1)
docs/                 architecture, threat model, ADRs, runbook, reviews
deploy/               systemd unit, Dockerfile
scripts/              dev-env setup, gated integration check
```

## Status & honesty

`go build ./...`, `go vet ./...` and `go test ./...` pass (see
`EXECUTION_PLAN.md` for the exact environment). Live WireGuard/iptables
integration is implemented but **not** verified in the development sandbox
(no kernel module / no root netlink there); run it on a disposable VM:

```bash
RUN_INTEGRATION=1 scripts/integration-check.sh
```

Nothing is claimed "production ready" until security and operational
evidence exists — see the debt ledger in `EXECUTION_PLAN.md`.

## License

Provided as-is for educational and operational use; see repository headers.
