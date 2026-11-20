# ADR-001: WireGuard as the tunnel substrate

Status: accepted (2026-11-20)

## Context

We need a secure, high-performance VPN dataplane in Go. Options: (a) custom
TLS/TCP overlay, (b) DTLS, (c) WireGuard kernel module, (d) wireguard-go userspace.

## Decision

Use **WireGuard** (kernel module preferred; wireguard-go fallback) as the only
tunnel substrate. `vpnd` never touches packet cryptography; it programs peers and
routes via netlink (`wgctrl`).

## Rationale

- Audited, formally verified protocol (Noise_IK); rolling our own would violate the
  master constraint (no custom crypto).
- Kernel WireGuard reaches line-rate forwarding with negligible overhead.
- The control plane (what this repo actually builds) is where the product value is:
  peer management, IPAM, firewall orchestration, API.

## Consequences

- Requires `CAP_NET_ADMIN` (ADR-006) for netlink programming.
- Userspace fallback available for environments without the kernel module
  (wireguard-go can be managed via the same wgctrl UAPI socket).

## Compliance

- No file in `internal/` may import `crypto/aes`, implement ciphers, or invent
  randomness for keys. Key generation is delegated to `wgtypes.GeneratePrivateKey`.
