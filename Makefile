# VPN_GOlang — operator makefile
GO ?= go
BIN := build
PKGS := ./...

.PHONY: all build test vet fmt lint clean install smoke integration

all: build test vet

build:
	$(GO) build -o $(BIN)/vpnd ./cmd/vpnd
	$(GO) build -o $(BIN)/vpnctl ./cmd/vpnctl

test:
	$(GO) test $(PKGS) -count=1

vet:
	$(GO) vet $(PKGS)

fmt:
	$(GO) fmt ./...

# integration runs against a disposable VM/CI container with wireguard +
# iptables present; refuses to run on a dev machine without the gate.
integration:
	@if [ "$$RUN_INTEGRATION" != "1" ]; then \
		echo "refusing: set RUN_INTEGRATION=1 on a disposable VM (AGENTS.md rule 5)"; exit 1; fi
	scripts/integration-check.sh

clean:
	rm -rf $(BIN)

install: build
	install -m 0755 $(BIN)/vpnd /usr/local/sbin/vpnd
	install -m 0755 $(BIN)/vpnctl /usr/local/bin/vpnctl

# local smoke: file-only operations, zero live-network mutation
smoke:
	$(GO) build -o $(BIN)/vpnd ./cmd/vpnd
	$(GO) build -o $(BIN)/vpnctl ./cmd/vpnctl
	$(BIN)/vpnctl init-server -output /tmp/vpnd-smoke/server.json \
		-token-path /tmp/vpnd-smoke/token -store /tmp/vpnd-smoke/peers.json -force
	$(BIN)/vpnd -config /tmp/vpnd-smoke/server.json -dry-run
