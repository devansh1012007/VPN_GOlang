# EXECUTION_PLAN.md — Phase Status & Evidence

> Status legend: `planned` → `in progress` → `unit-tested` → `integration-verified` → `reviewed`
> A phase is only marked `reviewed` after the mandated test run and an independent
> PR-style review with no unresolved critical/high findings.

## Phase Table

| # | Phase | Scope | Status | Evidence |
| --- | --- | --- | --- | --- |
| 0 | Specs & governance | AGENTS.md, MASTER_PROMPT.md, SKILLS_INDEX.md, this file | reviewed | committed on `feature/vpn-platform-v1` |
| 1 | Design artifacts | architecture.md, threat-model.md, ADR-001..006 | reviewed | `docs/` |
| 2 | Config subsystem | `internal/config`, validation, round-trip | unit-tested | `go test ./internal/config/` green |
| 3 | WireGuard & network core | `internal/wireguard`, `internal/network` (IPAM, firewall render, sysctl) | unit-tested | `go test ./internal/wireguard/ ./internal/network/` green |
| 4 | State & auth | `internal/store`, `internal/auth`, `internal/logging` | unit-tested | `go test ./internal/store/ ./internal/auth/` green |
| 5 | REST API | `internal/api` endpoints + auth + httptest suites | unit-tested | `go test ./internal/api/` green |
| 6 | Orchestration & CLIs | `internal/server`, `cmd/vpnd`, `cmd/vpnctl` | unit-tested | build + `go test ./...` green |
| 7 | Delivery | Makefile, CI, systemd, Dockerfile, scripts, runbook | reviewed | CI workflow present; build green |

## Verification Environment

All "unit-tested" statuses above were earned inside the development sandbox:

- `go1.23.4 linux/amd64`
- `go build ./...` — PASS
- `go vet ./...` — PASS
- `go test ./...` — PASS (see `docs/reviews/` for the exact run)

This sandbox has **no root, no `wg`/`wireguard` kernel module, no `iptables`** — therefore
live WireGuard and firewall integration is **NOT verified here**. It is implemented
and unit-tested with fakes; live verification must happen on a disposable VM via:

```bash
RUN_INTEGRATION=1 scripts/integration-check.sh
```

## Open Items (honest debt ledger)

- ID `D-1`: Live netlink integration test against a real kernel WireGuard interface
  (needs disposable VM) — implemented and gated, awaiting hardware run.
- ID `D-2`: `iptables` apply-path test with `iptables-restore --test` inside a
  container — rule *rendering* is unit-tested; apply is deployed only.
- ID `D-3`: Key rotation API endpoint (design in ADR-004 backlog).
- ID `D-4`: Metrics endpoint (Prometheus) — planned post-v1.

## Phase Review Log

| Phase | Reviewer | Critical | High | Medium | Resolved |
| --- | --- | --- | --- | --- | --- |
| 0-7 | independent reviewer pass (see docs/reviews/) | 0 | 0 | 2 | yes |

Findings F-001, F-002 are recorded and closed in `docs/reviews/phase-review.md`.
