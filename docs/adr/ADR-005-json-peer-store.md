# ADR-005: JSON file peer store with atomic writes

Status: accepted (2026-11-20)

## Context

Peer state must survive daemon restarts (idempotent reconciliation). Options:
SQLite, Postgres, a JSON file, a flat-directory of small files.

## Decision

A **single JSON document** (`internal/store`) holding all peer records, written
atomically (write temp file in same dir + `os.Rename`), mode 0600.

## Rationale

- v1 peer counts are tens-to-hundreds; a file is proportional and debuggable with
  `jq`.
- Atomic rename guarantees readers never see torn writes; crash leaves either old
  or new file.
- The `Store` interface is deliberately narrow (`Add`, `Get`, `List`, `Delete`,
  `AllocatedIPs`, `UpdateLastHandshake`) so a SQLite driver can replace it without
  touching callers.

## Consequences

- No SQL dependency in v1 (smaller supply chain).
- The file is not a database: concurrent writers are serialized by an in-process
  mutex; cross-process writes are unsupported (single-instance daemon).
- Store contains **public keys only**; client private keys are generated on the
  client and never leave it (threat model A1/A2 separation).
