# ADR-004: REST admin API, loopback-bound with bearer token

Status: accepted (2026-11-20)

## Context

Operators need programmatic peer management. Options: gRPC, a CLI that talks to
the store directly, or an HTTP REST API.

## Decision

A versioned **REST API** (`/api/v1/*`) served by `vpnd` on `127.0.0.1` by default,
authenticated with a **bearer token** (256-bit, generated with `crypto/rand`).

Endpoints:

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v1/status` | daemon + device + peer summary |
| GET | `/api/v1/peers` | list peers |
| POST | `/api/v1/peers` | add peer `{name, public_key}` |
| GET | `/api/v1/peers/{id}` | peer detail |
| DELETE | `/api/v1/peers/{id}` | remove peer |

## Rationale

- REST over loopback is auditable with `curl`, debuggable with any client, and does
  not require an RPC framework.
- Token (not mTLS) is enough for v1 because the surface is loopback-only; mTLS is a
  documented upgrade path when remote management lands.
- Remote exposure, when explicitly enabled by the operator, must front the API with
  a TLS-terminating proxy (runbook §remote-admin).

## Consequences

- All handlers take an interface (`ServerBackend`) — tests use a fake backend.
- Mutations are logged with actor context (T4).
- http.Server hard timeouts: read 5s, write 10s, idle 60s (T6).
