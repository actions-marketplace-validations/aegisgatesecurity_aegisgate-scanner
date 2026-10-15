# SPDX-License-Identifier: Apache-2.0
# AegisGate Scanner — Multi-stage Production Build (CLI Static Analysis Tool)
# =========================================================================
# Build (ML-enabled, default):
#   docker build -t aegisgate-scanner:latest .
#
# Build (heuristic-only / lite):
#   docker build --target lite -t aegisgate-scanner:lite .
#
# Run:
#   docker run --rm -v "$PWD:/github/workspace" aegisgate-scanner:latest scan /github/workspace
#
# AegisGate Scanner is a CLI tool for scanning AI artifacts — RAG document
# stores, training datasets, model configuration files, and agent skill
# packages — for prompt injection, PII exposure, hardcoded secrets, and
# compliance violations. It combines heuristic rules with an optional
# CNN-BiLSTM neural threat detector (ONNX Runtime) for ML-based detection.
#
# ML-enabled build (default target "ml"): CGO_ENABLED=1 with vendored
# ONNX Runtime shared library. Uses debian:bookworm-slim because
# onnxruntime prebuilt Linux shared libraries require glibc; Alpine's musl
# libc cannot load them.
#
# Heuristic-only build (target "lite"): CGO_ENABLED=0, pure static binary
# on gcr.io/distroless/static-debian12:nonroot. No ONNX Runtime, smaller
# image, suitable for environments where CGO/cross-compilation is
# undesirable.
#
# Hardening:
#   - Production stage runs as non-root.
#   - ML image purges libgnutls30 (Trivy gotcha #179 — eliminates 6
#     CRITICAL/HIGH alerts caused by gnutls transitive dependency).
#   - ML image keeps bash/dash (ONNX Runtime invokes /bin/sh internally)
#     but removes wget to reduce attack surface.
#   - No EXPOSE ports — this is a CLI tool, not a server.
#   - No HEALTHCHECK — CLI invocation is ephemeral.
# =========================================================================

# ---------------------------------------------------------------------------
# Builder stage: Go 1.27.2 on Debian bookworm.
# ---------------------------------------------------------------------------
FROM golang:1.27.2-bookworm AS builder

# Install C compiler + libc headers for CGO-based ONNX Runtime bindings.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy go.mod first for layer caching of module download.
COPY go.mod ./

# Copy the rest of the source tree (includes vendored lib/ and models/).
COPY . .

# Build arguments (overridable via --build-arg).
ARG CGO_ENABLED=1
ARG VERSION=0.4.0
ARG TARGETARCH

# CGO / ONNX Runtime environment.
# The vendored shared library lives at lib/${TARGETARCH}/libonnxruntime.so
# in the repo root, so we point the build-time linker there.
ENV CGO_ENABLED=${CGO_ENABLED}
ENV CGO_CFLAGS="-I/build/internal/onnxruntime_go"
ENV CGO_LDFLAGS="-L/build/lib/${TARGETARCH} -lonnxruntime -ldl"
ENV ONNXRUNTIME_SHARED_LIBRARY_PATH=/build/lib/${TARGETARCH}/libonnxruntime.so
ENV LD_LIBRARY_PATH=/build/lib/${TARGETARCH}

# Build the scanner binary.
RUN go build \
    -ldflags="-s -w -X main.Version=${VERSION}" \
    -o /aegisgate-scanner ./cmd/aegisgate-scanner/

# ===========================================================================
# Target: ml — ML-enabled scanner (CGO, ONNX Runtime, debian:bookworm-slim)
# ===========================================================================
FROM debian:bookworm-slim AS ml

ARG TARGETARCH

# Install runtime deps, then purge libgnutls30 to eliminate Trivy alerts
# (gotcha #179). We keep bash/dash because ONNX Runtime calls /bin/sh
# internally. We remove wget after all downloads/cleanups to harden the
# image attack surface.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libstdc++6 && \
    useradd -m -s /usr/sbin/nologin scanner && \
    mkdir -p /app/models /app/lib /github/workspace && \
    chown -R scanner:scanner /app /github/workspace && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /usr/lib/*/libgnutls.so.30* && \
    rm -f /var/lib/dpkg/info/libgnutls30.* && \
    sed -i '/libgnutls30/d' /var/lib/dpkg/status && \
    rm -f /usr/bin/wget

# Copy the scanner binary.
COPY --from=builder /aegisgate-scanner /app/aegisgate-scanner

# Copy the GitHub Action entrypoint script.
COPY entrypoint.sh /entrypoint.sh

# Copy the vendored ONNX Runtime shared library for the target arch.
COPY --from=builder /build/lib/${TARGETARCH}/libonnxruntime.so /app/lib/libonnxruntime.so
COPY --from=builder /build/lib/${TARGETARCH}/libonnxruntime.so.1 /app/lib/libonnxruntime.so.1

# Copy the CNN-BiLSTM threat detection model.
COPY --from=builder /build/models/threat_cnn_bilstm.onnx /app/models/threat_cnn_bilstm.onnx

# Runtime env: tell the scanner where to find ONNX Runtime.
ENV ONNXRUNTIME_SHARED_LIBRARY_PATH=/app/lib/libonnxruntime.so
ENV LD_LIBRARY_PATH=/app/lib

# WORKDIR for GitHub Action usage — host repo is mounted here.
WORKDIR /github/workspace

# Non-root.
USER scanner

# No EXPOSE — CLI tool, not a server.
# No HEALTHCHECK — CLI invocation is ephemeral.

ENTRYPOINT ["/entrypoint.sh"]

# ---------------------------------------------------------------------------
# Builder stage (lite): CGO_ENABLED=0 for pure static binary.
# ---------------------------------------------------------------------------
FROM golang:1.27.2-bookworm AS builder-lite

WORKDIR /build

COPY go.mod ./
COPY . .

ARG VERSION=0.4.0

ENV CGO_ENABLED=0

RUN go build \
    -ldflags="-s -w -X main.Version=${VERSION}" \
    -o /aegisgate-scanner ./cmd/aegisgate-scanner/

# ===========================================================================
# Target: lite — Heuristic-only scanner (CGO_ENABLED=0, distroless)
# ===========================================================================
FROM gcr.io/distroless/static-debian12:nonroot AS lite

# Copy the static binary from the lite builder (CGO=0).
COPY --from=builder-lite /aegisgate-scanner /app/aegisgate-scanner

# WORKDIR for GitHub Action usage — host repo is mounted here.
WORKDIR /github/workspace

# distroless static-debian12:nonroot already runs as non-root (UID 65532).

# No EXPOSE — CLI tool, not a server.
# No HEALTHCHECK — CLI invocation is ephemeral.

ENTRYPOINT ["/app/aegisgate-scanner"]