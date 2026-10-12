# SPDX-License-Identifier: Apache-2.0
# AegisGate Scanner — Makefile
# ============================================================================
# Standard targets for building, testing, and releasing AegisGate Scanner.
# Run `make help` for a list of available targets.
# ============================================================================

VERSION  := $(shell cat VERSION 2>/dev/null || echo 0.1.0)
BINARY   := aegisgate-scanner
CMD      := ./cmd/aegisgate-scanner
LDFLAGS  := -ldflags="-s -w -X main.Version=$(VERSION)"
GO       := go
GOFLAGS  := -count=1

.PHONY: help build build-ml build-lite test test-race test-cover cover lint fmt vet clean install uninstall release-snapshot

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: build-lite ## Build the scanner (heuristic-only, no CGO)

build-lite: ## Build heuristic-only binary (no CGO, no ONNX Runtime)
	CGO_ENABLED=0 $(GO) build $(LDFLAGS) -o $(BINARY) $(CMD)

build-ml: ## Build ML-enabled binary (requires CGO + ONNX Runtime)
	CGO_ENABLED=1 $(GO) build $(LDFLAGS) -o $(BINARY) $(CMD)

test: ## Run all tests
	$(GO) test ./... $(GOFLAGS)

test-race: ## Run tests with race detector
	$(GO) test -race ./... $(GOFLAGS)

test-cover: ## Run tests with coverage report
	$(GO) test -cover ./... $(GOFLAGS)

cover: ## Generate HTML coverage report
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

lint: vet ## Run linters (go vet + gofmt check)
	@echo "Checking gofmt..."
	@out=$$(gofmt -l . 2>&1); if [ -n "$$out" ]; then \
		echo "gofmt issues in:"; echo "$$out"; exit 1; \
	else echo "gofmt: OK"; fi

vet: ## Run go vet
	$(GO) vet ./...

fmt: ## Format all Go files
	gofmt -w .

clean: ## Remove build artifacts
	rm -f $(BINARY) coverage.out coverage.html

install: build-lite ## Install scanner to /usr/local/bin
	install -m 0755 $(BINARY) /usr/local/bin/$(BINARY)
	@echo "Installed: $$(which $(BINARY))"

uninstall: ## Remove scanner from /usr/local/bin
	rm -f /usr/local/bin/$(BINARY)
	@echo "Removed $(BINARY)"

release-snapshot: ## Build binaries for all platforms (snapshot, no signing)
	@for os in linux darwin; do \
		for arch in amd64 arm64; do \
			echo "Building $$os/$$arch..."; \
			GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 \
				$(GO) build $(LDFLAGS) -o $(BINARY)-$$os-$$arch $(CMD); \
		done; \
	done
	@echo "Snapshot binaries created."