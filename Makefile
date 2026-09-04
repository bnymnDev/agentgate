# agentgate — see CONTRIBUTING notes in docs/architecture.md
BINARY      := agentgate
BUILD_DIR   := bin
ECHO_SERVER := $(BUILD_DIR)/echo-server
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE)

GO ?= go

.PHONY: all build dev test e2e lint fmt vet docs clean install release-snapshot golden coverage

all: build

## build: compile the binary into bin/
build:
	@mkdir -p $(BUILD_DIR)
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BUILD_DIR)/$(BINARY) ./cmd/$(BINARY)
	@echo "built $(BUILD_DIR)/$(BINARY) $(VERSION)"

## install: go install the binary into GOBIN
install:
	$(GO) install -trimpath -ldflags '$(LDFLAGS)' ./cmd/$(BINARY)

$(ECHO_SERVER):
	@mkdir -p $(BUILD_DIR)
	$(GO) build -o $(ECHO_SERVER) ./testdata/servers/echo

## dev: run the proxy over HTTP against the demo server, with the web UI
dev: build $(ECHO_SERVER)
	@mkdir -p .agentgate
	AGENTGATE_ECHO=$(ECHO_SERVER) $(BUILD_DIR)/$(BINARY) run \
		--config testdata/policies/dev.yaml \
		--http 127.0.0.1:3333 \
		--ui 127.0.0.1:7777 \
		--log-level debug

## test: unit tests and golden files
test:
	$(GO) test ./...

## golden: regenerate the policy golden files, then read the diff
golden:
	$(GO) test ./internal/policy -update
	@git --no-pager diff --stat testdata/golden || true

## coverage: unit tests with a coverage profile
coverage:
	$(GO) test -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -func=coverage.out | tail -1

## e2e: build the binaries and drive them as real processes
e2e:
	$(GO) test -tags e2e -count=1 -timeout 5m ./e2e/...

## lint: golangci-lint, if it is installed
lint:
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint is not installed: https://golangci-lint.run/welcome/install/"; exit 1; }
	golangci-lint run

## fmt: gofmt every package
fmt:
	$(GO) fmt ./...
	gofmt -l -w $$(git ls-files '*.go')

## vet: go vet, including the e2e build tag
vet:
	$(GO) vet ./...
	$(GO) vet -tags e2e ./e2e/...

## docs: regenerate the generated tables in README.md and docs/
docs:
	$(GO) run ./internal/gendocs

## release-snapshot: build release artifacts locally without publishing
release-snapshot:
	@command -v goreleaser >/dev/null 2>&1 || { \
		echo "goreleaser is not installed: https://goreleaser.com/install/"; exit 1; }
	goreleaser release --snapshot --clean

clean:
	rm -rf $(BUILD_DIR) dist coverage.out .agentgate
