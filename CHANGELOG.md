# Changelog

All notable changes to AegisGate Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Patent Filed — October 12, 2026

- **US Provisional Patent Application No. 64/174,824** filed with USPTO.
  Title: "Systems and Methods for Static Analysis of Artificial Intelligence
  Training Artifacts for Security Threats." Inventor: Joshua Colvin. Micro
  Entity. Confirmation #9820. Patent Center #83060298. $65 filing fee.
  Claims priority to 64/153,573–64/153,577 (filed Sep 12, 2026).
  Non-provisional deadline: October 12, 2027.

### Added — v0.3.0: Detection Depth + Performance Sprint

- **Entropy-based secret detection** — Shannon entropy analysis catches
  unknown secrets that don't match any known regex format. Detects
  high-entropy strings near secret-related keywords (key, token, secret,
  password, bearer) and standalone high-entropy values. Configurable
  thresholds: 4.5 bits/char for base64-like, 3.0 for hex-only.
  New `internal/detectors/entropy.go` with `DetectEntropy()`.

- **Known example value suppression** — automatically suppresses findings
  that match known documentation examples (AWS docs keys, GitHub test
  tokens, Stripe test keys, JWT examples, etc.). Suppressed findings
  have confidence reduced to 0.1 with a "known example/test value" note.
  New `internal/detectors/examples.go` with `IsKnownExample()`,
  `IsExampleByContent()`, `FilterKnownExamples()`, `SuppressExamples()`.

- **Language-aware scanning** — file language detected from extension
  (Python, JS/TS, Go, Java, C/C++, Ruby, PHP, Shell, YAML, JSON, XML,
  HTML, SQL). Patterns with language metadata only run on matching files.
  Reduces false positives (e.g., Python `eval()` no longer fires on YAML
  configs) and improves performance (fewer regex passes per file).
  Dangerous function patterns tagged with language metadata. New
  `Language` type, `LanguageFromExtension()`, `LanguageFromPath()`,
  `DetectAllWithLanguage()`.

- **Regex merging for performance** — patterns within small categories
  merged into single alternation regex for one-pass scanning. Reduces
  regex calls from 268 to ~9 for categories under 3000-char threshold.
  Large categories (compliance, secrets) fall back to sequential scanning.
  Transparent to callers — `detectWithMerged()` used automatically.

- **Git history scanning** — new `scan-history` command scans git commit
  history for leaked secrets. Uses `git log --patch` to extract diffs,
  feeds added lines to detection engine + entropy analysis. Safeguards:
  max commit count (default 1000), max diff size (1MB), skip merge commits.
  New `pkg/scanner/history.go` with `ScanHistory()`, `HistoryResult`,
  `HistoryFinding` (includes commit hash, message, date, file path).

- **Pre-existing bug fix** — `yaml_long_string` pentest test was hanging
  due to stderr pipe buffer deadlock. Config validation error messages
  now truncate long values to 100 chars. Test now reads stderr in
  goroutine to prevent pipe deadlock.

### Performance — v0.3.0: Large File Scanning Optimization

- **Line-by-line keyword pre-filtering** — for files > 64KB, text is split
  into lines and processed in parallel. Each regex pattern has literal
  keywords extracted at compile time. Only patterns whose keywords appear
  on a given line are run against that line. 214 of 268 patterns have
  keywords; the remaining 54 (mostly PII patterns) scan full text in
  parallel. All patterns are single-line (no `(?s)` dotall) — lossless.
  Result: 12x faster scanning on 10MB files (227s → 18.3s).
- **O(log n) line/column lookup** — `byteOffsetToLineCol` was O(n) per
  match (scanning from byte 0 each time), consuming 38% of CPU on large
  files. Replaced with precomputed newline position table + binary search.

### Test Infrastructure — v0.3.0

- **Data race fix** — `bytes.Buffer` concurrent read/write in pentest
  tests (StdinHuge, OutputFormatFuzz) fixed with `sync.WaitGroup`.
- **Performance threshold guards** — time assertions now skip under
  `-short` flag (race detector adds 10-20x overhead).
- **Stress test gating** — 10MB, 1MB, self-scan, and high-density tests
  skip under `-short`. 50MB/100MB tests require `AEGISGATE_LONG_TESTS=1`.
- **ReDoS test timeout scaling** — 5s normal, 30s under `-short`.

### Added — v0.3.0: Content-Hash Caching

- **Content-hash scan caching** — skip re-scanning unchanged files across
  runs. Results cached by SHA-256(content), path-independent. Changing
  severity, disabled rules, or baselines does NOT invalidate cache.
  CLI: `--cache`, `--cache-dir`, `--clear-cache`. Config: `cache_enabled`,
  `cache_dir`. New `pkg/cache/` package (264 LOC + 331 LOC tests).
- **Cache eviction** — LRU by insertion time (`cache_max_entries`) and
  age-based (`cache_max_age` in hours). Both default to 0 (unlimited).
  `EvictNow()` for manual eviction. Applied on load and on put.

### Fixed — v0.3.0

- **Version string** — `var Version` in main.go updated from `0.1.0-dev`
  to `0.3.0` (was only correct via ldflags in Makefile builds).

### Documented — v0.3.0

- **Dataflow/taint tracking limitation** — documented in README under
  "Known Limitations". Scanner performs static pattern matching, not
  AST-level dataflow analysis. Recommends Semgrep/CodeQL as complementary
  tools for code-level taint tracking.

### Removed — v0.3.0

- **Technical Debt marker detection** — removed `technical-debt` category
  (8 patterns: BUG, FIXME, HACK, XXX, TODO, NOTE, security-flagged,
  not-implemented). These are code-quality linting patterns, not security
  detection. Pattern count: 276 → 268. Categories: 10 → 9.

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
- **TODO/FIXME detector** — 8 patterns (BUG, FIXME, HACK, XXX, TODO, NOTE,
  security-flagged markers, not-implemented markers). New `technical-debt`
  category. *(Removed in v0.3.0 — not a security detection category.)* Total
  patterns at v0.2.0: 276.
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