# Changelog

All notable changes to AegisGate Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Solo Maintainer ROI Features (v0.2.0-dev)
- **JSONL output format** (`--format jsonl`) — NDJSON with one finding per line
  plus a summary line. Ideal for piping to jq, Splunk, ELK, Datadog.
  New `pkg/output/jsonl.go` with `FormatJSONL()`.
- **Full slog structured logging migration** — all 44 `fmt.Fprintf(os.Stderr)`
  diagnostic calls converted to Go's `log/slog` structured logger.
  New global flags: `--log-level` (debug/info/warn/error) and `--log-format`
  (text/json). Config file support via `log_level` and `log_format` fields.
  `--verbose` maps to debug level. JSON format enables machine-readable
  log lines for SIEM/log aggregation. New `cmd/aegisgate-scanner/logger.go`.
- **`doctor` command** — self-test that scans a directory, reports binary info,
  config status, detection pattern counts, scan results with severity/category
  breakdown, and operational verdict. Use cases: post-install verification,
  conference demos, CI smoke tests.
- **TODO/FIXME detector** — 8 new patterns (BUG, FIXME, HACK, XXX, TODO, NOTE,
  security-flagged markers, not-implemented markers). New `technical-debt`
  category. Total patterns: 276 (up from 268).
- **Makefile** — standard build targets: build, build-lite, build-ml, test,
  test-race, test-cover, cover, lint, vet, fmt, clean, install, release-snapshot.
- **Install script** (`install.sh`) — curl-based installer with OS/arch
  detection, SHA256 checksum verification, and `VARIANT=lite|ml` support.
- **Homebrew formula** (`Formula/aegisgate-scanner.rb`) — for `brew install`.
- **Init config template** updated with `log_level` and `log_format` fields.

### Changed
- `runScan()` signature now accepts `globalLogLevel` and `globalLogFormat` params
- Progress bar gated on text log format (prevents JSON log line corruption)
- `--quiet` only suppresses stdout output, not diagnostic logging (preserves
  original semantics where `--verbose` and `--quiet` are independent)
- Help text updated with global options section and `doctor` command

### Roadmap — Post-v0.2.0
- Content-hash scan caching (skip unchanged files across runs)
- Streaming scan mode for large files (chunk-based processing)
- Competitive benchmark report (vs TruffleHog, Gitleaks, Semgrep)
- Transformer-based ML model upgrade path (DistilBERT/BERT)
- Multimodal artifact support (image-based prompt injection)
- Model weight analysis (backdoor detection)

## [0.1.0] — 2026-10-12

### Added — Core Detection Engine
- Detection engine ported from AegisGate Rampart (223 regex patterns)
- ML threat detection stack ported from AegisGate MCP (CharCNN-BiLSTM v13)
- Evasion-resistant text normalization (homoglyph, l33t, zero-width, Unicode)
- PII detection (US core, US extended, financial, international)
- Secret detection (65 credential patterns)
- XSS detection (11 patterns)
- OT/ICS protocol detection (10 patterns)
- Compliance pattern detection (35 patterns)
- OWASP LLM Top 10 prompt injection detection
- MITRE ATLAS adversarial ML threat detection
- Zero external module dependencies (all third-party code vendored)
- Dual build modes: CGO (neural) and non-CGO (heuristic-only)
- Apache 2.0 license, DCO enforcement

### Added — CLI Features
- `scan` command with directory walking and file classification
- `init` command for config file generation
- `version` command with build info (Go version, platform, CGO status)
- `help` command and `--help`/`-h` flags
- `--format` flag: SARIF 2.1.0, JSON, text output formats
- `--output` flag: write results to file instead of stdout
- `--severity` flag: minimum severity threshold (critical/high/medium/low)
- `--no-ml` flag: disable ML detection (regex-only mode)
- `--no-color` flag: disable ANSI color output
- `--quiet`/`-q` flag: suppress output (exit code only)
- `--verbose`/`-v` flag: verbose output with progress messages
- stdin/pipe support: `cat file | aegisgate-scanner scan -`
- `--stdin-ext` flag: file extension for stdin classification
- `--concurrency` flag: parallel scanning with worker pool
- `--fail-on` flag: severity-based exit code threshold
- `--disable-rule` flag: per-rule enable/disable (repeatable)
- `--baseline` flag: load baseline suppression file
- `--generate-baseline` flag: save current findings as baseline
- Progress indicator for large scans (>10 files, stderr, throttled 500ms)

### Added — Dangerous Function Detection (34 patterns)
- Python: eval, exec, os.system, subprocess shell=True, os.popen, __import__,
  pickle.loads, yaml.load, marshal.loads, compile, ctypes, input→exec chain
- JavaScript/TypeScript: eval, Function constructor, child_process.exec/spawn,
  setTimeout/setInterval string, document.write, innerHTML
- General: SQL injection, command injection, hardcoded URLs
- URL/endpoint: raw IP addresses, localhost, non-standard ports, WebSocket,
  AWS/GCP service endpoints
- Base64 payloads: b64decode, atob, env var blobs, eval chain (CRITICAL)

### Added — Configuration
- `.aegisgate.yml` YAML config file with auto-discovery
- Custom rules: user-defined regex patterns with name/severity/category
- Baseline suppression: JSON file of reviewed/accepted findings
- .gitignore support: full glob parser (*, **, ?, [], !, /) with hierarchy
- Per-rule enable/disable via config or CLI
- Fail-on-severity for CI/CD exit code control
- Config validation with helpful error messages

### Added — Output Formats
- SARIF 2.1.0 with CWE/OWASP LLM Top 10 references and remediation guidance
- Structured JSON with scan metadata, stats, and findings
- Human-readable text with color-coded severity
- Per-rule remediation guidance in all formats
- Rule metadata: CWE ID, OWASP LLM Top 10 mapping, references

### Added — Infrastructure
- Multi-stage Dockerfile: ML target (debian:bookworm-slim, ONNX Runtime,
  gnutls purged) and lite target (distroless, CGO=0)
- GitHub Action (action.yml) for CI/CD integration
- CI workflow: DCO check, lint, test (lite + ML), race detection, build,
  Docker build verification
- Security workflow: govulncheck, gosec, Trivy, gitleaks, trufflehog,
  opsec scan, SBOM generation
- Release workflow: multi-arch builds, cosign signing, SBOM attestation,
  GitHub Release with release notes
- Pre-commit hook for pre-commit framework
- OPSEC pre-commit hooks (secret detection, path detection, etc.)
- CGO build tags for accurate runtime CGO detection

### Added — Testing
- 95.4% coverage for cmd/aegisgate-scanner (all testable paths)
- 100% coverage for pkg/output
- 97.2% coverage for pkg/config
- 97.1% coverage for pkg/scanner
- 94.7% coverage for internal/detectors
- 91.3% coverage for pkg/artifacts
- 90.2% coverage for pkg/baseline
- Performance benchmarks (8 benchmarks: regex, ML, full pipeline, utilities)
- Edge case tests (12 tests: large files, empty, binary, Unicode, deep
  nesting, 1000 files, BOM, CRLF, permissions, extensions, ignore, no files)
- Concurrent scanning tests with race condition verification
- stdin/pipe integration tests (30 tests)
- Error-path tests for all CLI functions
- Parity gate verification with AegisGate Rampart (223 base patterns match)

### Fixed
- Symlink handling: split Walk() into Walk() + walkInternal() with shared
  inode map for loop detection. Fixed filepath.SkipDir on symlinked dirs
  skipping remaining siblings. EvalSymlinks before recursive walks.
- Concurrent map writes panic: replaced package-level regex finding map
  with per-artifact buildRegexFindingLines() returning local map
- Dockerfile lite builder: separate builder-lite stage with CGO=0 (distroless
  can't run dynamically-linked binaries)
- ldflags path: use main.Version instead of full import path for -X flag
- CGO detection: replaced placeholder with build-tag conditional files