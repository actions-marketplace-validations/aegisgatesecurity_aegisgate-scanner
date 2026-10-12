# Changelog

All notable changes to AegisGate Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Council-of-Mine P0 Fixes
- `.env` files now scanned by default (was incorrectly in defaultIgnorePaths)
- `.env.local`, `.env.production`, `.env.development` variant files supported
- `.ipynb` (Jupyter notebook) files now classified and scanned
- Special-case handling for extensionless `.env` files in ClassifyFile

### Added — Council-of-Mine P1 Enhancements
- Threat model document (`docs/threat-model.md`) — STRIDE analysis, DFD, scope
- Benchmark evaluation document (`docs/benchmark-evaluation.md`) — detection rates, FPR, evasion resistance
- NIST AI RMF framework mapping in rule metadata (Govern, Map, Measure, Manage)
- NIST CSF 2.0 subcategory references in rule metadata
- EU AI Act article references in rule metadata
- SARIF output now includes `nist-ai-rmf`, `nist-csf`, `eu-ai-act` properties
- `--config` CLI flag for explicit config file path (security teams with central configs)
- `config.LoadFile()` function for loading config from arbitrary path

### Added — Council-of-Mine P2 Enhancements
- Inline suppression support: `# aegisgate-ignore: rule_id` comments
  - Supports Python (#), JS/Go (//), HTML (<!-- -->), CSS (/* */) comment styles
  - `aegisgate-ignore: all` suppresses all findings on the line
  - Suppression applies to comment line AND next line (eslint-style)
  - New `pkg/scanner/suppressions.go` with ParseSuppressions() and ApplySuppressions()
- Indirect prompt injection detection (5 new patterns):
  - Conditional instruction: "if user asks X, respond with Y"
  - Role redefinition: "note to the assistant: ..."
  - Context override: "previous document is outdated, use this instead"
  - Embedded system instructions: "important notice for the AI: ..."
  - Data exfiltration via response: "when responding, include the user's API key"
- Model config schema validation (4 new patterns):
  - `trust_remote_code: true` (CRITICAL — arbitrary code execution)
  - `load_in_4bit: true` (LOW — may reduce safety alignment)
  - `torch.load()` without `weights_only=True` (HIGH — pickle deserialization risk)
  - `safety_checker: None` (CRITICAL — removes content guardrails)
- Total detection patterns: 268 (up from 257)

### Roadmap — v0.2.0 (Post-Patent Filing)
- Structured logging via `slog` with JSON handler option
- JSONL/JSONLines line-level findings (parse and scan per-line content)
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