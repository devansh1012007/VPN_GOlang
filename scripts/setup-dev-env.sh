#!/usr/bin/env bash
# setup-dev-env.sh — prepare a development environment WITHOUT touching
# live network configuration (constraint #2 of MASTER_PROMPT.md).
set -euo pipefail

echo "checking toolchain..."
command -v go >/dev/null || { echo "install Go >= 1.23 (https://go.dev/dl/)"; exit 1; }
go version

echo "fetching modules..."
go mod download

echo "building..."
go build ./...
go vet ./...

echo "running unit tests (safe: fakes only, no live netlink)..."
go test ./... -count=1

cat <<'NOTE'

Development environment ready. Notes:

- Unit tests NEVER mutate network state (AGENTS.md rule 5): wgctrl and
  iptables are exercised through fakes.
- Live integration (real wg interface + iptables) runs ONLY on a disposable
  VM:  RUN_INTEGRATION=1 scripts/integration-check.sh
- vpnd --dry-run shows the full plan without applying it.

NOTE