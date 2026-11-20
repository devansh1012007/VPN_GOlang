# ADR-006: Privilege & failure semantics

Status: accepted (2026-11-20)

## Context

Configuring interfaces, routes, and firewall rules requires elevated privileges
on Linux. Running a whole daemon as root widens blast radius.

## Decision

- `vpnd` requires `CAP_NET_ADMIN` (root or capability-bounded user). Link
  creation/removal, netlink programming, sysctl, and iptables are the only
  privileged operations; everything else (API, store I/O) is ordinary file/IO
  work under the same identity but separate packages.
- All mutations are **idempotent and reversible**: `Apply()` twice is a no-op;
  `TearDown()` removes exactly what `Apply()` created (tracked rule sets,
  interface owned by the daemon).
- SIGTERM/SIGINT → graceful shutdown (stop API, flush store, optionally remove
  interface if `remove_interface_on_stop=true`). SIGHUP → reload config and
  reconcile.
- Link creation uses netlink (`ip link add`) — not shell-outs — to avoid exec of
  binaries influenced by PATH.

## Rationale

- Idempotence + tracked teardown make recovery from crashes safe: re-run `Apply`.
- Capability model (rather than setuid helpers) matches how wg-quick handles
  the same problem, with fewer moving parts.

## Consequences

- No `sudo`/exec from the daemon anywhere.
- In containers: run with `--cap-add=NET_ADMIN` (deploy/Dockerfile).
- A future hardening step (open item D-4+): seccomp profile restricting syscalls.
