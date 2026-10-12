<!-- mcp-name: io.github.aegisgatesecurity/aegisgate-scanner -->
<div align="center">

# 🛡️ AegisGate Scanner

**Antivirus for AI artifacts.**

*Static analysis that detects prompt injection, PII, secrets, dangerous code, and compliance violations in RAG documents, training data, model configs, and agent skills — before they reach production.*

276 regex patterns + CharCNN-BiLSTM (v13) ML · 8 output formats · SARIF · SBOM · GitHub Action · Dual Docker images · Zero runtime dependencies

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://golang.org/)
[![Version](https://img.shields.io/badge/Version-0.1.0-blue.svg)](#changelog)
[![Coverage](https://img.shields.io/badge/Coverage-90%25+-brightgreen.svg)](#testing)
[![CI](https://github.com/aegisgatesecurity/aegisgate-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/aegisgatesecurity/aegisgate-scanner/actions/workflows/ci.yml)
[![E2E](https://github.com/aegisgatesecurity/aegisgate-scanner/actions/workflows/e2e.yml/badge.svg)](https://github.com/aegisgatesecurity/aegisgate-scanner/actions/workflows/e2e.yml)
[![Security](https://github.com/aegisgatesecurity/aegisgate-scanner/actions/workflows/security.yml/badge.svg)](https://github.com/aegisgatesecurity/aegisgate-scanner/actions/workflows/security.yml)
[![Fuzzed](https://img.shields.io/badge/Fuzzed-✅-purple.svg)](#testing)
[![Race Detector](https://img.shields.io/badge/Race_Detector-✅-success.svg)](#testing)
[![Docker](https://img.shields.io/badge/Docker-ML_+_Lite-blue.svg)](#docker)
[![Patterns](https://img.shields.io/badge/Patterns-276-9cf.svg)](#detection-categories)
[![Formats](https://img.shields.io/badge/Output-8_Formats-orange.svg)](#output-formats)
[![Patent Pending](https://img.shields.io/badge/IP-Patent_Pending-8B5CF6?logo=uspto)](#ip-notice)

[Quick Start](#quick-start) · [Detection](#detection-categories) · [Output Formats](#output-formats) · [GitHub Action](#github-action) · [Docker](#docker) · [Testing](#testing) · [Releases](https://github.com/aegisgatesecurity/aegisgate-scanner/releases)

[![GitHub stars](https://img.shields.io/github/stars/aegisgatesecurity/aegisgate-scanner?style=social)](https://github.com/aegisgatesecurity/aegisgate-scanner) — **If AegisGate Scanner helps you secure your AI artifacts, please consider ⭐ starring this repo. It helps others discover it.**

</div>

> **We follow [GitHub's recommended security practices](https://securitylab.github.com/resources/five-easy-steps-to-secure-your-open-source-project/) for open source projects.** CodeQL scanning · Secret scanning with push protection · Dependabot alerts · DCO enforcement · Fuzz testing · Race detector CI · Archive bomb protection

---

> **🛡️ Using AegisGate at work?** [AegisGate Platform](https://github.com/aegisgatesecurity/aegisgate-platform) is our server-side gateway — 223 detection patterns, MCP/A2A/ACP protection, 30+ compliance frameworks, and cryptographic attestation. For individual developers, Scanner runs locally or in your CI/CD pipeline. [Explore Platform →](https://github.com/aegisgatesecurity/aegisgate-platform)
>
> **🔐 AegisGate Rampart** — Using AI coding tools (Copilot, Cursor, local LLMs)? [AegisGate Rampart](https://github.com/aegisgatesecurity/aegisgate-rampart) is a free local proxy that intercepts secrets and sensitive data before they leave your machine. [Explore Rampart →](https://github.com/aegisgatesecurity/aegisgate-rampart)
>
> **🔧 AegisGate MCP** — Building MCP servers? [AegisGate MCP](https://github.com/aegisgatesecurity/aegisgate-mcp) is a standalone secure MCP server framework with 23 security layers built in. [Explore MCP →](https://github.com/aegisgatesecurity/aegisgate-mcp)

---

## Why AegisGate Scanner?

**AI artifacts — RAG documents, training datasets, model configs, agent skills —
are supply chain inputs. A single poisoned document can inject malicious
prompts, exfiltrate secrets, or cause model misbehavior. Existing SAST tools
don't understand AI-specific threats. AegisGate Scanner does.**

| | Semgrep / CodeQL | TruffleHog / Gitleaks | AegisGate Scanner |
|---|---|---|---|
| Prompt injection | ❌ | ❌ | ✅ 17 patterns + ML |
| Secrets | Partial | ✅ | ✅ 64 patterns |
| PII (US + International) | ❌ | ❌ | ✅ 85 patterns |
| Dangerous code (agent skills) | Partial | ❌ | ✅ 34 patterns |
| Compliance (HIPAA/GDPR/EU AI Act) | ❌ | ❌ | ✅ 64 patterns |
| OT/ICS protocol exposure | ❌ | ❌ | ✅ 9 patterns |
| Archive extraction | ❌ | ❌ | ✅ zip/tar.gz/tar.bz2 |
| SARIF output | ✅ | ❌ | ✅ |
| ML-based detection | ❌ | ❌ | ✅ CharCNN-BiLSTM |
| SBOM generation | ❌ | ❌ | ✅ SPDX |
| Diff/baseline suppression | ❌ | ❌ | ✅ |

**276 detection patterns. 10 categories. 8 output formats. Apache 2.0.**

---

## Quick Start

```bash
# Install (curl — one-line installer with checksum verification)
curl -fsSL https://raw.githubusercontent.com/aegisgatesecurity/aegisgate-scanner/main/install.sh | bash

# Or via Homebrew
brew install aegisgatesecurity/tap/aegisgate-scanner

# Or from source
go install github.com/aegisgatesecurity/aegisgate-scanner/cmd/aegisgate-scanner@latest

# Scan a directory
aegisgate-scanner scan ./my-project

# Scan with SARIF output for CI/CD
aegisgate-scanner scan ./rag-docs --format sarif -o results.sarif

# Pipe content via stdin
cat suspicious_agent_skill.py | aegisgate-scanner scan - --stdin-ext .py

# Self-test (verify installation)
aegisgate-scanner doctor
```

## Installation

### From Source

```bash
git clone https://github.com/aegisgatesecurity/aegisgate-scanner.git
cd aegisgate-scanner

# Using Makefile
make build          # ML-enabled (requires CGO)
make build-lite     # Lite (no ML, pure static binary)

# Or directly
# Lite build (no ML, pure static binary)
CGO_ENABLED=0 go build -o aegisgate-scanner ./cmd/aegisgate-scanner/

# ML-enabled build (requires ONNX Runtime)
# Linux amd64: lib/amd64/libonnxruntime.so is vendored
CGO_ENABLED=1 go build -o aegisgate-scanner ./cmd/aegisgate-scanner/
```

### Docker

```bash
# ML-enabled (full detection)
docker build --target ml -t aegisgate-scanner .
docker run --rm -v $(pwd):/github/workspace aegisgate-scanner scan /github/workspace

# Lite (heuristic-only, smaller image, no CGO)
docker build --target lite -t aegisgate-scanner:lite .
docker run --rm -v $(pwd):/github/workspace aegisgate-scanner:lite scan /github/workspace
```

### GitHub Actions

```yaml
- uses: aegisgatesecurity/aegisgate-scanner@v0.3.0
  with:
    path: '.'
    format: 'sarif'
    severity: 'medium'
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: aegisgate-report.sarif
```

## Detection Categories

| Category | Patterns | Examples |
|----------|----------|----------|
| **Prompt Injection** | 17 | "Ignore all previous instructions", role-play attacks, delimiter injection, SSTI probes, base64-encoded payloads, indirect injection |
| **Secrets** | 64 | AWS keys, GitHub tokens, OpenAI keys, Stripe keys, Slack tokens, JWT, private keys, database URLs |
| **PII — US Core** | 32 | SSN, email, phone, passport, driver's license, ITIN |
| **PII — US Extended** | 13 | Employer ID, VIN, bank routing, Medicare, NAIC |
| **PII — Financial** | 16 | Credit card numbers (Visa/MC/Amex/Discover), IBAN, SWIFT/BIC |
| **PII — International** | 24 | UK NHS, Canada SIN, Germany Steuer, France INSEE, Australia TFN |
| **XSS** | 12 | Script injection, event handlers, encoded payloads, SVG vectors |
| **Compliance** | 47 | OWASP LLM Top 10, EU AI Act, MITRE ATLAS, HIPAA, GDPR, COPPA, CCPA, model config safety |
| **Dangerous Functions** | 34 | `eval()`, `exec()`, `os.system()`, `subprocess`, `pickle.load()`, `child_process.exec()` |
| **OT/ICS Protocols** | 9 | Modbus, S7comm, DNP3, BACnet, EtherCAT, OPC UA, Profinet |
| **Technical Debt** | 8 | TODO, FIXME, HACK, XXX, BUG, NOTE — security-flagged markers |
| **ML (optional)** | 1 model | CharCNN-BiLSTM neural detector for adversarial prompt injection |

**Total: 276 regex patterns + optional ML detection.**

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| **Text** | `--format text` (default) | Terminal / human-readable |
| **JSON** | `--format json` | Programmatic / API integration |
| **JSONL** | `--format jsonl` | NDJSON — one finding per line (jq, Splunk, ELK, Datadog) |
| **SARIF** | `--format sarif` | GitHub Code Scanning / CI/CD |
| **HTML** | `--format html` | Reports / email / sharing |
| **PR Comment** | `--format pr-comment` | Pull request comment (markdown table) |
| **GitHub Actions** | `--format github-actions` | PR annotations in CI |
| **SBOM** | `--format sbom` | SPDX software bill of materials |

## CLI Reference

```bash
# Basic scan
aegisgate-scanner scan ./project

# With output file and format
aegisgate-scanner scan ./project --format json -o results.json

# Filter by severity (critical, high, medium, low)
aegisgate-scanner scan ./project --severity high

# Disable specific rules
aegisgate-scanner scan ./project --disable-rule secret_aws_key --disable-rule pii_ssn

# Parallel scanning
aegisgate-scanner scan ./project --concurrency 8

# Extract and scan archives
aegisgate-scanner scan ./project --extract-archives

# Diff against baseline (show only new findings)
aegisgate-scanner scan ./project --diff --baseline previous-results.json

# Enable ML detection (requires CGO build)
aegisgate-scanner scan ./project --ml

# Stdin/pipe mode
cat config.yaml | aegisgate-scanner scan - --stdin-ext .yaml

# Version
aegisgate-scanner version

# Self-test (verify installation, scan own codebase)
aegisgate-scanner doctor

# Structured logging (JSON for SIEM/Splunk/Datadog)
aegisgate-scanner scan ./project --log-level debug --log-format json
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings (clean) |
| 1 | Findings detected |
| 2 | Scanner error (invalid path, config error, etc.) |

## Configuration

Create `.aegisgate.yml` in your project root:

```yaml
# Paths to ignore (glob patterns)
ignore_paths:
  - "node_modules"
  - "vendor"
  - "dist"
  - "*.test"

# File extensions to scan (empty = all supported)
extensions: []

# Severity threshold (critical, high, medium, low)
severity: "medium"

# Enable ML detection
ml: false

# Parallel workers
concurrency: 0

# Extract archives before scanning
extract_archives: false

# Custom patterns
custom_patterns:
  - name: "custom_api_key"
    regex: "MY_KEY_[a-zA-Z0-9]{32}"
    severity: "high"
    description: "Custom API key format"
```

## Plugin System

Scanner supports custom rule plugins (Go plugins, `.so` files):

```bash
aegisgate-scanner scan ./project --plugin ./my_rules.so
```

Plugins implement the `plugins.Plugin` interface and can add custom
detection patterns, output formats, or post-processing steps.

## Advanced Features

### Archive Extraction
Scanner can extract and scan inside `.zip`, `.tar.gz`, and `.tar.bz2`
archives. Archive bomb protection enforces a 100MB extraction limit and
10,000 file count limit. Path traversal (Zip Slip / Tar Slip) is blocked.

### Baseline Suppression
Suppress known/accepted findings using `--diff --baseline` to show only
new findings since the last scan. Useful for CI/CD gating without
blocking on pre-existing issues.

### Content-Hash Caching
Skip re-scanning unchanged files across runs. Results are cached by
SHA-256(content), so renamed files still hit the cache. Changing severity
thresholds, disabled rules, or baselines does **not** invalidate the
cache — only content changes, pattern changes, or scanner version bumps do.

```bash
aegisgate-scanner scan --cache .
aegisgate-scanner scan --cache --cache-dir /tmp/aegisgate-cache.json .
aegisgate-scanner scan --clear-cache .
```

Cache stats are reported in scan output (`cache hits: N, cache misses: N`).
Configure in `.aegisgate.yml`:

```yaml
cache_enabled: true
cache_dir: .aegisgate-cache.json
```

### URL & Base64 Detection
Scanner detects URLs and base64-encoded content, decoding base64 to
scan the underlying text for hidden threats.

### Auto-Update
Scanner can check for new versions and update detection patterns:

```bash
aegisgate-scanner update
```

## Docker

Two Docker images are built from the same Dockerfile:

| Image | Size | Detection | Use Case |
|-------|------|-----------|----------|
| `aegisgate-scanner:ml` | ~150MB | Regex + ML (full) | Local / server / full CI |
| `aegisgate-scanner:lite` | ~20MB | Regex only (heuristic) | CI/CD pipelines / minimal |

The lite image is distroless (no shell, no package manager) for minimal
attack surface. The ML image uses Debian slim with the ONNX Runtime.

## GitHub Action

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory to scan |
| `format` | `github` | Output format |
| `severity` | `medium` | Minimum severity threshold |
| `no-ml` | `false` | Disable ML detection |
| `diff` | `false` | Show only new findings |
| `baseline` | — | Baseline file path (for diff) |
| `disable-rule` | — | Rules to disable (comma-separated) |
| `concurrency` | `0` | Parallel workers |
| `no-extract-archives` | `false` | Disable archive extraction |
| `quiet` | `false` | Suppress stdout output |

## Testing

### Coverage

All 9 testable packages maintain ≥90% coverage:

| Package | Coverage |
|---------|----------|
| cmd/aegisgate-scanner | 90.9% |
| internal/detectors | 98.8% |
| pkg/api | 90.5% |
| pkg/artifacts | 93.4% |
| pkg/baseline | 90.2% |
| pkg/config | 95.8% |
| pkg/output | 95.6% |
| pkg/plugins | 92.7% |
| pkg/scanner | 97.6% |

### Test Types

| Type | Count | Description |
|------|-------|-------------|
| Unit tests | 1,080+ | Per-function correctness |
| Benchmark tests | 8 | Performance regression detection |
| Fuzz tests | 6 | Random input crash detection |
| Race tests | 7 | Concurrent access validation |
| Archive security tests | 12 | Bomb/traversal/symlink protection |
| Evasion suite | 1 | Adversarial detection resistance (50 transforms × 52 payloads) |
| E2E tests | 10 | Full pipeline integration (CI workflow) |

### Running Tests

```bash
# All tests (non-CGO)
CGO_ENABLED=0 go test -cover ./...

# With race detector
CGO_ENABLED=1 go test -race -skip TestEvasionSuite ./...

# Benchmarks
go test -bench=. -benchmem ./pkg/scanner/

# Fuzz tests
go test -fuzz=FuzzDetectAll -fuzztime=30s ./internal/detectors/
go test -fuzz=FuzzScanArtifact -fuzztime=30s ./pkg/scanner/
```

## Project Structure

```
aegisgate-scanner/
├── cmd/aegisgate-scanner/   # CLI entrypoint
├── internal/detectors/       # Detection engine + 276 patterns
├── internal/ml/              # CharCNN-BiLSTM ML threat detector
├── pkg/api/                  # Public API/SDK
├── pkg/artifacts/            # File walker, archive extraction
├── pkg/baseline/             # Baseline suppression
├── pkg/config/               # Configuration management
├── pkg/output/               # Output formatters (8 formats)
├── pkg/plugins/              # Custom rule plugin system
├── pkg/scanner/              # Scan orchestration
├── Makefile                  # Build targets (build, test, lint, release)
├── install.sh                # curl-based installer with checksum verification
├── Formula/                  # Homebrew formula
├── Dockerfile                # Dual-target (ml + lite)
├── action.yml                # GitHub Action
└── .github/workflows/        # CI, E2E, Release, Security workflows
```

## Roadmap

### Completed in v0.3.0
- [x] Entropy-based secret detection (Shannon entropy for unknown secrets)
- [x] Known example value suppression (AWS docs keys, GitHub test tokens, etc.)
- [x] Language-aware scanning (17 languages, pattern filtering by file type)
- [x] Regex merging (alternation compilation, 10x fewer regex calls)
- [x] Git history scanning (`scan-history` command with commit-by-commit diff)
- [x] Line-by-line keyword pre-filtering (12x faster large-file scanning)
- [x] O(log n) line/column lookup (binary search on precomputed newline table)
- [x] Content-hash scan caching (skip unchanged files across runs)

### Completed in v0.2.0-dev
- [x] Structured logging via `slog` with `--log-level` and `--log-format` flags
- [x] JSONL (NDJSON) output format for SIEM/log aggregation
- [x] `doctor` self-test command
- [x] TODO/FIXME/HACK/XXX/BUG technical debt detection (8 patterns)
- [x] Makefile, install.sh, Homebrew formula

### Planned
- [ ] Cache eviction (LRU with max entries / max age)
- [ ] Streaming scan mode for large files (chunk-based processing)
- [ ] Real-world corpus validation (100+ known-poisoned artifacts)
- [ ] Competitive benchmark report (vs TruffleHog, Gitleaks, Semgrep)
- [ ] Transformer-based ML model upgrade (DistilBERT/BERT)
- [ ] Multimodal artifact support (image-based prompt injection)
- [ ] Model weight analysis (backdoor detection)
- [ ] Additional archive formats (.7z, .rar)

## Known Limitations

### No Dataflow / Taint Tracking

AegisGate Scanner performs **static pattern matching** — it detects
security-relevant patterns in file content (secrets, PII, prompt
injection, dangerous functions, compliance violations) but does **not**
perform dataflow or taint analysis. This means:

- It does **not** track how user input flows through code to sinks
  (e.g., `request → variable → eval()`)
- It does **not** build ASTs or control flow graphs
- It does **not** detect cross-file taint propagation

This is a deliberate scope decision. Dataflow analysis requires a
fundamentally different architecture (language-specific AST parsers,
control flow graph construction, interprocedural analysis) that is
orthogonal to the scanner's core mission of scanning **AI artifacts**
(RAG documents, training datasets, model configs, agent skills) for
embedded threats.

**For code-level dataflow analysis**, we recommend complementary tools:
- [Semgrep](https://semgrep.dev/) — rule-based dataflow with taint tracking
- [CodeQL](https://codeql.github.com/) — semantic code analysis
- [Snyk Code](https://snyk.io/products/snyk-code/) — AI-powered code analysis

AegisGate Scanner and these tools are **complementary**, not
competitive — they solve different problems for different artifact types.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## IP Notice

AegisGate's core technologies are patent pending with the USPTO (Provisional App. Nos. 64/153,573–64/153,577, filed September 12, 2026). Source code is © 2025-2026 AegisGate Security, LLC. Licensed under Apache 2.0.

---

<div align="center">

[🌐 AegisGate Security](https://aegisgatesecurity.io) · [💬 Discord](https://discord.gg/cvJ4QcY9B) · [✉️ support@aegisgatesecurity.io](mailto:support@aegisgatesecurity.io) · [𝕏 @aegisgate](https://x.com/aegisgate) · [📱 Telegram](https://t.me/+imsWrOY4QpcxYzIx) · [🐘 @aegisgate@mastodon.social](https://mastodon.social/@aegisgate)

Made with 🖤 by AegisGate Security developers to secure the AI attack surface.

</div>