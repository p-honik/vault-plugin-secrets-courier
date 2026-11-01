BINARY := bin/vault-plugin-secrets-courier

# The version comes from the git tag (v0.1.0, or v0.1.0-3-gabc1234[-dirty] between
# tags). Without any tag it falls back to a development version. Override with
# `make build VERSION=v0.1.0`.
VERSION ?= $(shell git describe --tags --dirty 2>/dev/null || echo v0.0.0-dev)
PKG := github.com/p-honik/vault-plugin-secrets-courier/internal/backend

.PHONY: build version test vet fmt live-test
build:
	go build -trimpath -ldflags="-s -w -X $(PKG).Version=$(VERSION)" -o $(BINARY) ./cmd/vault-plugin-secrets-courier

version:
	@echo $(VERSION)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

# Runs the plugin inside a real Vault server (`vault server -dev`). Set VAULT_BIN
# to a Vault 1.18 binary, for example:
#   VAULT_BIN=/path/to/vault make live-test
live-test:
	@test -n "$(VAULT_BIN)" || (echo "set VAULT_BIN to a vault binary" && exit 1)
	VAULT_BIN=$(VAULT_BIN) go test -tags live -count=1 -v ./internal/livetest
