<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2024-2026 AegisGate Security, LLC -->

# Contributing to AegisGate Scanner

Thank you for your interest in contributing to AegisGate Scanner!

## DCO (Developer Certificate of Origin)

All commits must be signed off with `git commit -s` to indicate your
agreement with the [Developer Certificate of Origin](https://developercertificate.org/).

See [DCO.md](DCO.md) for full details.

## Build

```bash
# Non-CGO (heuristic-only, static binary)
CGO_ENABLED=0 go build -o aegisgate-scanner ./cmd/aegisgate-scanner/

# CGO (full ML, requires libonnxruntime.so)
CGO_ENABLED=1 \
  CGO_CFLAGS="-I$(pwd)/internal/onnxruntime_go" \
  CGO_LDFLAGS="-L$(pwd)/lib/amd64 -lonnxruntime -ldl" \
  ONNXRUNTIME_SHARED_LIBRARY_PATH=$(pwd)/lib/amd64/libonnxruntime.so \
  LD_LIBRARY_PATH=$(pwd)/lib/amd64 \
  go build -o aegisgate-scanner ./cmd/aegisgate-scanner/
```

## Test

```bash
# Non-CGO tests (heuristic-only)
CGO_ENABLED=0 go test -v -cover ./...

# CGO tests (full ML)
CGO_ENABLED=1 \
  CGO_CFLAGS="-I$(pwd)/internal/onnxruntime_go" \
  CGO_LDFLAGS="-L$(pwd)/lib/amd64 -lonnxruntime -ldl" \
  ONNXRUNTIME_SHARED_LIBRARY_PATH=$(pwd)/lib/amd64/libonnxruntime.so \
  LD_LIBRARY_PATH=$(pwd)/lib/amd64 \
  go test -v -cover ./...

# Race detector
CGO_ENABLED=1 go test -race -count=1 ./...
```

## Docker

```bash
# Full ML image
docker build -t aegisgate-scanner:latest .

# Heuristic-only (lite) image
docker build --build-arg CGO_ENABLED=0 --target lite -t aegisgate-scanner:lite .
```

## Pre-commit Hooks

```bash
git config core.hooksPath .githooks
```

This enables OPSEC scanning, gofmt, and go vet on every commit.

## Code Style

- `gofmt` is mandatory — CI will reject unformatted code
- `go vet` must pass
- No external dependencies — all third-party code is vendored into `internal/`
- Test coverage must be ≥ 90%

## License

All contributions are made under the Apache License, Version 2.0.