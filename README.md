# AegisGate Scanner

**Antivirus for AI Artifacts.**

Static analysis that detects prompt injection, PII, secrets, dangerous code,
and compliance violations in RAG documents, training data, model configs,
and agent skills — before they reach production.

[![CI](https://github.com/aegisgatesecurity/aegisgate-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/aegisgatesecurity/aegisgate-scanner/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.26-blue.svg)](https://go.dev/)
[![Coverage](https://img.shields.io/badge/Coverage-90%25+-green.svg)](#testing)

---

## Why

AI artifacts — RAG documents, training datasets, model configs, agent skills —
are supply chain inputs. A single poisoned document can inject malicious
prompts, exfiltrate secrets, or cause model misbehavior. Existing SAST tools
don't understand AI-specific threats. AegisGate Scanner does.

**257 detection patterns** across 10+ categories, with optional ML-based
threat detection powered by an ONNX neural model.

## Quick Start

```bash
# Install (from source)
go install github.com/aegisgatesecurity/aegisgate-scanner/cmd/aegisgate-scanner@latest

# Scan a directory
aegisgate-scanner scan ./my-project

# Scan with SARIF output for CI/CD
aegisgate-scanner scan ./rag-docs --format sarif -o results.sarif

# Pipe content via stdin
cat suspicious_agent_skill.py | aegisgate-scanner scan - --stdin-ext .py
```

## Installation

### From Source

```bash
git clone https://github.com/aegisgatesecurity/aegisgate-scanner.git
cd aegisgate-scanner

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
- uses: aegisgatesecurity/aegisgate-scanner@v0.1.0
  with:
    path: '.'
    format: 'sarif'
    severity: 'medium'
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: aegisgate-report.sarif
```

See [action.yml](action.yml) for all available inputs.

## Features

### Detection

| Category | Patterns | Examples |
|----------|----------|---------|
| **Prompt Injection** | 15+ | "Ignore all previous instructions", system prompt extraction, jailbreak attempts |
| **OWASP LLM Top 10** | 20+ | All 10 OWASP LLM categories (2025): LLM01–LLM10 |
| **MITRE ATLAS** | 10+ | Adversarial tactics: reconnaissance, resource development, collection, exfiltration |
| **Secrets** | 20+ | AWS access keys, GCP service accounts, GitHub tokens, private keys, database URLs |
| **PII — US Core** | 12+ | SSN, passport, driver's license, ITIN, phone numbers |
| **PII — International** | 15+ | UK NHS, Canadian SIN, German tax ID, French INSEE, Brazilian CPF |
| **PII — Financial** | 10+ | Credit card numbers (Visa, MC, Amex, Discover), SWIFT/BIC, IBAN |
| **Dangerous Functions** | 30+ | `eval()`, `exec()`, `os.system()`, `pickle.loads()`, `child_process.exec()` |
| **URL/Endpoint Detection** | 6 | Raw IP URLs, localhost, non-standard ports, WebSocket, AWS/GCP endpoints |
| **Base64 Payloads** | 4 | Python `b64decode`, JS `atob`, env var blobs, eval chains |
| **XSS** | 5+ | Stored, reflected, DOM-based XSS patterns |
| **Compliance** | 5+ | CCPA references, ANP (Brazil), consumer rights, minor protection |

### ML Threat Detection (Optional)

When built with CGO enabled, the scanner loads an ONNX neural model that
detects sophisticated prompt injection and jailbreak attempts that regex
patterns miss. The model is vendored — no external dependencies.

```bash
# ML-enabled scan (default if built with CGO)
aegisgate-scanner scan ./docs

# Disable ML, use regex-only
aegisgate-scanner scan ./docs --no-ml
```

### Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| **Text** | `--format text` | Terminal output with colored severity (default) |
| **JSON** | `--format json` | Programmatic consumption, custom pipelines |
| **SARIF** | `--format sarif` | GitHub Code Scanning, Azure DevOps, other SARIF consumers |
| **HTML** | `--format html` | Self-contained report with sortable table and severity badges |
| **PR Comment** | `--format pr-comment` | GitHub PR markdown comment with finding summary |
| **GitHub Actions** | `--format github-actions` | `::error`/`::warning`/`::notice` annotations for CI |
| **SBOM** | `--format sbom` | SPDX 2.3 JSON software bill of materials |

### Advanced Features

- **Stdin/Pipe Support** — `cat file.json | aegisgate-scanner scan - --stdin-ext .json`
- **Diff Scanning** — `--diff main` scans only files changed vs base branch
- **Archive Extraction** — Automatically extracts `.zip`, `.tar.gz`, `.tar.bz2` with path traversal protection
- **Baseline Suppression** — `--generate-baseline baseline.json` then `--baseline baseline.json` to suppress known findings
- **Per-Rule Disable** — `--disable-rule dangerous_py_eval` to skip specific rules
- **Severity-Based Exit Codes** — `--fail-on high` exits non-zero only for HIGH/CRITICAL findings
- **Plugin System** — Custom YAML patterns in `.aegisgate-plugins/` directory
- **API/SDK** — Embed scanning in Go applications via `pkg/api`
- **Auto-Update** — `aegisgate-scanner update` checks GitHub releases and self-updates
- **Concurrent Scanning** — `--concurrency 8` for parallel file scanning
- **Progress Indicator** — Throttled progress output to stderr during scans
- **Gitignore Support** — `RespectGitIgnore: true` in config honors `.gitignore` files
- **Config File** — `.aegisgate.yml` for project-specific scan configuration

## Configuration

Create a `.aegisgate.yml` in your project root:

```bash
aegisgate-scanner init
```

```yaml
# .aegisgate.yml
min_severity: medium
output_format: sarif
no_ml: false
concurrency: 0  # 0 = auto-detect
extract_archives: true
respect_gitignore: true

# Custom ignore paths (merged with defaults)
ignore_paths:
  - "vendor"
  - "third_party"

# Disable specific rules
disabled_rules:
  - "xss_stored_basic"
```

### Plugin System

Create custom detection rules in YAML:

```bash
mkdir .aegisgate-plugins
cat > .aegisgate-plugins/custom-rules.yml << 'EOF'
rules:
  - id: custom_internal_api
    name: custom_internal_api
    severity: high
    regex: 'https://internal\.mycompany\.com/v[0-9]+/'
    description: "Internal API URL detected in artifact"
    category: "custom"
EOF
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings (scan passed) |
| 1 | Findings detected (scan failed) |
| 2 | Configuration or runtime error |

## API/SDK

Embed AegisGate Scanner in Go applications:

```go
import "github.com/aegisgatesecurity/aegisgate-scanner/pkg/api"

scanner, err := api.NewScanner()
if err != nil {
    log.Fatal(err)
}

// Scan a directory
result, err := scanner.ScanPath("./my-project")
if err != nil {
    log.Fatal(err)
}

for _, finding := range result.Findings {
    fmt.Printf("%s: %s in %s:%d\n",
        finding.Severity, finding.RuleID, finding.File, finding.Line)
}

// Scan content directly (stdin/pipe)
result, err = scanner.ScanContent("agent_skill.py", []byte(content))
```

See [pkg/api](pkg/api/) for full API documentation.

## Docker Images

| Target | Size | CGO | ML | Use Case |
|--------|------|-----|----|----------|
| `ml` (default) | ~150MB | Yes | Yes | Full detection including neural model |
| `lite` | ~20MB | No | No | Heuristic-only, static binary, distroless |

```bash
# Pull from GHCR (when published)
docker pull ghcr.io/aegisgatesecurity/aegisgate-scanner:latest
docker pull ghcr.io/aegisgatesecurity/aegisgate-scanner:lite
```

## Testing

```bash
# Run all tests (non-CGO)
CGO_ENABLED=0 go test ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

# Run ML tests (requires ONNX Runtime)
CGO_ENABLED=1 go test -timeout 180s ./...

# Race detector
go test -race -count=1 ./...
```

All packages maintain ≥90% test coverage. See [CI](.github/workflows/ci.yml)
for the full test pipeline.

## Detection Metadata

Detection rules include CWE (Common Weakness Enumeration) and OWASP LLM Top 10
references where applicable. SARIF output includes this metadata for integration
with security dashboards and compliance reporting.

**Note:** As of v0.1.0, detailed CWE/OWASP metadata is available for the 22
core OWASP LLM Top 10 and MITRE ATLAS rules. Remaining rules receive
category-based fallback mappings. Full per-rule metadata is targeted for v0.2.0.

## Roadmap

- [v0.2.0] Complete CWE/OWASP metadata for all 257 rules
- [v0.2.0] Semgrep-compatible custom rule format
- [v0.2.0] SARIF suppression file format
- [v0.2.0] Pre-commit hook for local scanning
- [Future] Hugging Face Hub integration (scan models before download)
- [Future] LangChain/LlamaIndex integration (scan at ingestion time)
- [Future] Custom ML model training pipeline

## Project Structure

```
aegisgate-scanner/
├── cmd/aegisgate-scanner/   # CLI entrypoint
├── internal/detectors/      # Detection engine (257 patterns)
├── internal/ml/             # ONNX neural model integration
├── pkg/api/                 # Public API/SDK
├── pkg/artifacts/           # File walker, archive extraction
├── pkg/baseline/            # Baseline suppression
├── pkg/config/              # Configuration management
├── pkg/output/              # Output formatters (7 formats)
├── pkg/plugins/             # Custom rule plugin system
├── pkg/scanner/             # Scan orchestration
├── Dockerfile               # Dual-target (ml + lite)
├── action.yml               # GitHub Action
└── .github/workflows/       # CI, Release, Security workflows
```

## License

Apache-2.0. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

**AegisGate Scanner** is part of the AegisGate security platform.
For enterprise features — centralized management, multi-repo scanning,
policy enforcement, and compliance reporting — see
[AegisGate Platform](https://aegisgatesecurity.io).