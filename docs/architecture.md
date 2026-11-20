# Architecture

## System Context

```mermaid
graph TB
    subgraph Operator machine
        A[vpnctl CLI]
    end
    subgraph VPN server host
        B[vpnd daemon]
        C[WireGuard kernel interface: wg0]
        D[iptables rules]
        E[Peer store JSON]
        F[REST API 127.0.0.1:8080]
    end
    subgraph VPN clients
        G[Peer A - laptop]
        H[Peer B - phone]
        I[Peer C - VM]
    end

    A -- "admin ops (token auth)" --> F
    F --> B
    B -- "generic netlink (wgctrl)" --> C
    B -- "idempotent apply/remove" --> D
    B -- "atomic writes" --> E
    C <== "WireGuard protocol UDP:51820" ==> G
    C <== "WireGuard protocol" ==> H
    C <== "WireGuard protocol" ==> I
```

## Component View (in-process)

```mermaid
graph LR
    subgraph cmd/vpnd
        M[main: flag parsing, signals]
    end
    subgraph internal/server
        S[Server orchestrator]
    end
    subgraph internal/wireguard
        W[DeviceManager - wgctrl]
    end
    subgraph internal/network
        N1[IPAM pool]
        N2[Firewall renderer]
        N3[Sysctl]
    end
    subgraph internal/store
        P[PeerStore]
    end
    subgraph internal/api
        R[REST API]
    end
    subgraph internal/config
        CFG[Config loader/validator]
    end
    subgraph internal/auth
        T[Token auth]
    end

    M --> S
    S --> CFG
    S --> W
    S --> N1
    S --> N2
    S --> N3
    S --> P
    S --> R
    R --> T
    R --> S
```

## Data Flow: peer provisioning

1. Operator calls `POST /api/v1/peers` with the peer public key + name.
2. API validates token (`internal/auth`, constant-time compare).
3. Server asks IPAM for a free address inside `network.address` (persisted allocation).
4. Peer record (key, address, name, timestamps) is persisted by PeerStore (atomic tmp+rename).
5. `DeviceManager.AddPeer` programs the peer into the kernel via wgctrl.
6. Firewall renderer refreshes rules (masquerade + forward + per-peer rules).
7. Operator can render the client-side config via `vpnctl` and hand it to the peer.

## Security boundaries

| Boundary | Control |
| --- | --- |
| Internet ↔ WireGuard UDP port | WireGuard cryptographic handshake (Noise_IK); no custom crypto anywhere. |
| Host ↔ admin REST API | API binds 127.0.0.1 by default; bearer token with constant-time comparison. |
| vpnd ↔ kernel | wgctrl via generic netlink; requires `CAP_NET_ADMIN` (see ADR-006). |
| Store ↔ disk | Atomic writes; file mode 0600; store contains public keys only, never private keys of peers. |

## Failure & recovery

- Store is the source of truth for desired peer state; kernel state is reconciled
  from it on every start (idempotent reconciliation loop).
- SIGHUP triggers config reload + reconcile; SIGTERM/SIGINT tears down what the
  daemon created (interface removal optional, controlled by config).
