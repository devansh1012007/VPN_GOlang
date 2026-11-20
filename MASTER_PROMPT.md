# MASTER_PROMPT.md — VPN Platform in Go

## Mission

Build a **complete, maintainable, secure, feature-rich VPN platform in Go** — not a
demo that merely establishes an encrypted tunnel. The platform must be something an
operator could deploy, run, and extend.

## Non-Negotiable Constraints

1. **Never implement custom cryptographic primitives.** All tunnel cryptography is
   provided by WireGuard (kernel module or wireguard-go userspace implementation).
   Key material handling uses `golang.zx2c4.com/wireguard/wgctrl/wgtypes`.
2. **Never modify live network configuration of the development machine during
   development.** Live configuration changes are confined to integration test
   environments (disposable VMs) and production deployment paths.
3. **Preserve existing working results.** Nothing gets deleted in favor of a
   rewrite without a superseding ADR.
4. **Work on a dedicated Git branch. Do not push to any remote.**
5. **Honesty:** No feature may be claimed as working without test evidence.
   No "production ready" claim without security and operational evidence.

## Workflow (per engineering phase)

1. Load relevant skills from `SKILLS_INDEX.md` before starting the phase.
2. Complete a read-only audit of the current repository and environment state.
3. Produce/refresh: architecture diagram, threat model, ADRs, detailed plan.
4. Implement the phase.
5. Run the mandated test suite; record evidence.
6. Obtain an independent PR-style review; fix all critical/high findings.
7. Only then proceed to the next phase.

## Feature Scope (target)

### Server (`cmd/vpnd`)
- Manage a WireGuard interface end-to-end (create, configure, reload, teardown)
  through the kernel WireGuard generic-netlink API via `wgctrl`.
- Peer lifecycle management: add / update / remove / list peers, each with an
  allocated VPN address from a managed IP pool (IPAM).
- REST admin API (loopback by default, token-authenticated) exposing peer
  management and server status.
- Firewall orchestration: render and apply iptables rules for NAT (masquerading),
  forwarding, and per-peer access control; idempotent apply/remove.
- Kernel parameter management (IP forwarding, relevant sysctls).
- Durable peer state (JSON store with atomic writes) so restarts are harmless.
- Structured logging; graceful shutdown; privilege-aware operation.

### Client CLI (`cmd/vpnctl`)
- Initialize a client config with a generated key pair (via `wgtypes` — no custom RNG).
- Register with a server by printing a config-block or API request.
- Render a ready-to-use `wg-quick`-compatible config file.
- Diagnostics: show effective config, generated keys, assigned address.

### Platform qualities
- Config validation with precise error messages.
- `go vet` clean; table-driven unit tests across `internal/`.
- Deployment assets: systemd unit, Dockerfile, CI workflow.
- Documentation: architecture (with diagram), STRIDE threat model, runbook, ADRs.

## Success Criteria (for the whole platform)

- `go build ./...` succeeds; `go vet ./...` is clean.
- All unit tests pass (`go test ./...`).
- Integration tests exist and are clearly gated for VM execution.
- Every external interface (API, config, CLI) has a stable, documented contract.
- The docs describe exactly what is verified vs. what needs a live host.
