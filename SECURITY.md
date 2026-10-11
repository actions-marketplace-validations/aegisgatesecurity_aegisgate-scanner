<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2024-2026 AegisGate Security, LLC -->

# Security Policy

## Supported Versions

AegisGate Scanner follows semantic versioning.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Security Architecture

AegisGate Scanner is a static analysis tool for AI artifacts. It scans files
in CI/CD pipelines and local development environments for security threats
before deployment. The scanner operates entirely offline — no network
connections are made during scanning.

### Detection Layers

| Layer | Protection | Mode |
|-------|-----------|------|
| L1 | Regex pattern matching (223 patterns) | Heuristic |
| L2 | Compliance pattern matching (35 patterns) | Heuristic |
| L3 | CharCNN-BiLSTM neural threat detection (v13) | Neural (CGO) |
| L4 | Evasion-resistant text normalization | Heuristic |
| L5 | PII detection (US core, US extended, financial, international) | Heuristic |
| L6 | Secret detection (65 credential patterns) | Heuristic |

### Dual Build Modes

| Mode | CGO | ML | Binary Size | Docker Image |
|------|-----|----|-------------|--------------|
| Full | `CGO_ENABLED=1` | Neural (ONNX Runtime) | ~15MB | ~140MB (debian:bookworm-slim) |
| Lite | `CGO_ENABLED=0` | Heuristic-only | ~8MB | ~2MB (distroless) |

### Artifact Classes Scanned

| Class | File Types | Threats Detected |
|-------|-----------|-----------------|
| RAG documents | .txt, .md, .json, .jsonl, .csv, .html | Prompt injection, PII, secrets |
| Training datasets | .jsonl, .csv, .json | Data poisoning, PII, secrets |
| Model configs | .yaml, .yml, .json | Tool poisoning, insecure configs |
| Agent skills | .json, .yaml, .py, .ts | Prompt injection, code injection |

### Supply Chain Security

- **Zero external module dependencies** (no `require` directives in go.mod)
- All third-party code vendored: onnxruntime_go (MIT), libonnxruntime.so (MIT, Microsoft), golang.org/x/text (BSD-3-Clause)
- Model integrity verified via SHA-256 hash at load time
- Binary signing via Sigstore/cosign (keyless, OIDC)

## Security Features

| Tool | Purpose | Frequency |
|------|---------|-----------|
| **govulncheck** | Go vulnerability database | Every push |
| **gosec** | Static security analysis | Every push |
| **Trivy** | Container & filesystem scan | Every push + weekly |
| **Gitleaks** | Secret detection (git history) | Every push |
| **TruffleHog** | Verified secret detection | Every push |
| **go vet** | Standard Go analysis | Every push |
| **OPSEC scan** | Private paths, internal docs, secrets | Every push + pre-commit |
| **SBOM** | CycloneDX + SPDX generation | Every push + releases |

## Reporting a Vulnerability

**DO NOT open a public GitHub issue for security vulnerabilities.**

Email: security@aegisgatesecurity.io

Please include:
1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a fix or mitigation within
90 days. Valid vulnerability reports may be eligible for a bounty.