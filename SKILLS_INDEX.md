# SKILLS_INDEX.md — Skill Load Matrix

Which skills/knowledge areas must be loaded (read in full) before starting each
phase. "Loaded" means the agent has read the artifact and the ADRs listed.

| Phase | Required reading before coding |
| --- | --- |
| 0 — Specs | `AGENTS.md`, `MASTER_PROMPT.md` |
| 1 — Design | `docs/adr/*` (all), WireGuard official docs overview, `golang.zx2c4.com/wireguard/wgctrl` package docs |
| 2 — Config | ADR-003 (config & key layout), Go `encoding/json` docs |
| 3 — WG/network | ADR-001, ADR-002, `wgctrl` client API, `wgtypes` key API, Linux `ip(8)`/`iptables(8)` man page summaries, ADR-006 |
| 4 — Store/auth | ADR-005, Go `os` atomic-write patterns, `crypto/subtle` |
| 5 — API | ADR-004, Go `net/http`, `httptest` |
| 6 — CLIs | `cobra`-free std `flag` docs, ADR-004, internal/server API |
| 7 — Delivery | systemd unit conventions, Docker multi-stage builds, GitHub Actions Go workflow |

## Hard rules (apply to all phases)

- Never load or invoke a skill that mutates live network state.
- Crypto-relevant code must reference the ADR that authorizes the approach.
- After each phase, append evidence links to `EXECUTION_PLAN.md`.
