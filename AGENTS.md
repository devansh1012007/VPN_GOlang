# AGENTS.md — Agent Collaboration Spec

This file governs how engineering agents (human or AI) contribute to this repository.

## Ground Rules

1. **Read before you write.** Read `MASTER_PROMPT.md`, `EXECUTION_PLAN.md`, and the
   relevant `docs/adr/*` records before touching code. If your change contradicts
   an ADR, update the ADR first (or write a superseding one), then change code.
2. **Phased execution.** Work in the phases defined by `EXECUTION_PLAN.md`. Each phase
   must end with: (a) all phase tests green, (b) documentation updated,
   (c) a review pass described in `docs/reviews/<phase>.md` before the next phase starts.
3. **Branch discipline.** All work happens on `feature/*` branches off `main`.
   Never push to a remote unless the maintainer says so. Never force-push.
4. **No home-rolled crypto.** All cryptography comes from WireGuard itself and from
   vetted Go libraries. Any PR that introduces a hand-written cipher, PRNG, or
   protocol padding scheme is rejected without review.
5. **No live-network mutations from dev machines.** Tests and examples must never
   modify a developer machine's live routing table, firewall, or sysctls. Anything
   that touches real interfaces is gated behind integration tests that only run
   on disposable VMs (see `scripts/integration-check.sh`).
6. **Honesty in status.** A feature is "done" only when its tests pass in the
   environment where it was verified. "Production ready" claims require security
   and operational evidence linked from `EXECUTION_PLAN.md`.

## Review Protocol (PR-style)

Every phase gets an independent review before merge:

- Reviewer must not be the author of the change under review.
- Review report template lives at `docs/reviews/template.md`.
- Blocking severities: **critical** (security, data loss, broken build) and
  **high** (broken feature, missing test for a security control). A phase cannot
  be marked complete with an unresolved critical/high finding.
- Findings are addressed in a follow-up commit referencing the finding ID
  (e.g. `fix(P3): F-017 leak of config path in logs`).

## Commit Message Format

```
<type>(<phase>): <summary>

<body: what and why, tests added, evidence>
```

Types: `feat`, `fix`, `docs`, `test`, `chore`, `refactor`.

## Testing Requirements

| Layer | Requirement |
| --- | --- |
| Unit tests | Every exported function in `internal/` has at least one table-driven test. |
| API tests | Every REST endpoint has happy-path + auth-failure tests via `httptest`. |
| Integration | Gated behind `RUN_INTEGRATION=1` on a disposable VM with `wg` available. |
| Build | `go build ./...` and `go vet ./...` must pass on every commit. |

## Documentation Debt

If you knowingly leave something unfinished, open a `TODO(<phase>):` comment with
an issue link, and record it in `EXECUTION_PLAN.md` under "Open Items". Silent
partial implementations are not acceptable.
