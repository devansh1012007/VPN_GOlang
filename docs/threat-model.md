# Threat Model (STRIDE)

Scope: the VPN platform (`vpnd`, `vpnctl`, REST API, peer store, firewall
orchestration). WireGuard protocol itself is out of scope (audited elsewhere);
we trust its Noise_IK handshake and ChaCha20-Poly1305/AEAD data protection.

## Assets

| ID | Asset | Impact if lost |
| --- | --- | --- |
| A1 | Server private key (in `server.json`) | Total VPN impersonation / MITM of all peers |
| A2 | Peer public-key registry (store) | Attacker can revoke/steal client slots |
| A3 | Admin API token | Attacker can add own peer (network access) |
| A4 | VPN subnet routing / NAT rules | Traffic blackhole, privilege escalation to host net |
| A5 | Peer availability (DoS) | Service outage |

## Trust boundaries

- TB1: Internet → WireGuard UDP socket (protocol-protected).
- TB2: Local admin → REST API (token).
- TB3: `vpnd` → kernel (netlink, requires CAP_NET_ADMIN).
- TB4: disk → peer store (file permissions).

## STRIDE analysis

| ID | Threat (category) | Vector | Mitigation in this platform | Residual |
| --- | --- | --- | --- | --- |
| T1 | **S**poof peer | Attacker replays old peer key | WireGuard handshake authenticates by keypair; only keys present on the wg device can complete handshake | none known |
| T2 | **S**poof admin | Stolen API token | Token is 256-bit random from `crypto/rand` (via wgctrl-independent auth pkg); constant-time compare; API loopback-only by default; token file 0600 | rotate periodically (D-3) |
| T3 | **T**amper store | Local file edit by non-root | Store written atomically with 0600; directory expected root-only | needs fs enforcement on host |
| T4 | **R**epudiation: admin actions | Operator denies change | All mutating API calls are logged with peer id + action (structured log) | log shipping is host-side concern |
| T5 | **I**nformation disclosure: private key in logs | Log statements dumping config | Config marshal path redacts private key (`redacted()` on config); tested by `config_test.go` | none |
| T6 | **D**oS: API | Unauthenticated request flood | API is loopback-only default; `http.Server` with timeouts (Read/Write/Idle) set | full DoS protection out of scope |
| T7 | **D**oS: VPN port | Packet flood on UDP/51820 | WireGuard is silent to unauthenticated packets (baked into protocol) | measured rate limits out of scope |
| T8 | **E**levation of privilege: peer → host | Client VPN peer pivots into host network | Firewall renderer only allows forward between VPN subnet and NAT, not host LAN rules; per-peer `allowed` groups restrict; document defaults in ADR-001 | operator must review rendered rules |
| T9 | **E**levation via vpnd itself | Binary runs as root | ADR-006 privilege separation: root only needed for netlink; API+store handlers run without elevated fs access; graceful shutdown; no shell-outs from config paths | full seccomp profile future work |

## Security requirements traced to code

| Req | Control | Where |
| --- | --- | --- |
| SR-1 | No custom crypto | whole repo; enforced by review rule in `AGENTS.md` |
| SR-2 | Keys only via `wgtypes` | `internal/wireguard/peers.go` |
| SR-3 | Constant-time token check | `internal/auth/token.go` (`crypto/subtle`) |
| SR-4 | Atomic store writes | `internal/store/store.go` |
| SR-5 | API loopback + timeouts | `internal/api/server.go` |
| SR-6 | Redacted private key in any marshaling | `internal/config/config.go` |
| SR-7 | Idempotent firewall apply/remove | `internal/network/firewall.go` |

## Out of scope (explicit)

- Host hardening (unattended-upgrades, auditd): deployment runbook §host.
- DDoS scrubbing upstream of the server.
- Peer endpoint roaming abuse (WireGuard handles it).
