BINARY := bin/vault-plugin-secrets-courier

.PHONY: build test vet fmt live-test
build:
	go build -trimpath -ldflags="-s -w" -o $(BINARY) ./cmd/vault-plugin-secrets-courier

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
