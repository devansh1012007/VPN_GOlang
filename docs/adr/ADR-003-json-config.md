# ADR-003: JSON configuration files

Status: accepted (2026-11-20)

## Context

Server, store, and client all need configuration artifacts. Options: YAML, TOML,
protobuf, INI, JSON.

## Decision

**JSON** via stdlib `encoding/json`, one file per role:

- `testdata/server.json` shape: interface settings, network, store path, API, firewall.
- Client config render is additionally `wg-quick` compatible (INI-like) as output
  from `vpnctl`.

## Rationale

- Zero added dependencies (YAML/TOML need third-party parsers — more supply chain).
- Go stdlib JSON is memory-safe, well-fuzzed, and produces precise line numbers via
  `json.SyntaxError` for good UX.
- Diff-friendly and machine-mergeable; the peer store is also JSON (ADR-005).

## Consequences

- No comments inside JSON — schema documentation lives in `internal/config/config.go`
  field docs and in the runbook.
- Private key of the server is serialized as a JSON field `private_key` but always
  **redacted** (`REDACTED`) in any "safe print" path (SR-6 in threat model).
- Validation is explicit and fail-fast at load time; every field error names the
  JSON path.
