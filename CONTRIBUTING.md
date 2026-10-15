# Contributing to AegisGate Scanner

Thank you for your interest in improving AegisGate Scanner! This document
covers the process for contributing code, reporting issues, and suggesting
features.

## Prerequisites

- Go 1.26+
- Git
- For ML features: ONNX Runtime (vendored for Linux amd64)

## Getting Started

```bash
git clone https://github.com/aegisgatesecurity/aegisgate-scanner.git
cd aegisgate-scanner
go build ./cmd/aegisgate-scanner/
go test ./...
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feat/my-feature
```

### 2. Make Changes

Follow these conventions:

- **SPDX header** required on all new `.go` files:
  ```go
  // SPDX-License-Identifier: Apache-2.0
  package mypackage
  ```
- **gofmt** — all code must be formatted: `gofmt -w .`
- **go vet** — must pass: `go vet ./...`
- **Test coverage** — all packages must maintain ≥90% coverage
- **No external dependencies** — the scanner must remain air-gapped capable

### 3. Test

```bash
# Non-CGO tests
CGO_ENABLED=0 go test ./...

# With coverage
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

# ML tests (slower, requires CGO)
CGO_ENABLED=1 go test -timeout 180s ./...

# Race detector
go test -race -count=1 ./...
```

### 4. Commit (DCO Required)

Every commit must include a `Signed-off-by` line (Developer Certificate of Origin):

```bash
git commit -s -m "feat: add new detection pattern for XYZ

Description of what was added and why.

Signed-off-by: Your Name <your.email@example.com>"
```

The `-s` flag adds the Signed-off-by line automatically.

### Commit Message Convention

Follow conventional commits:

| Type | Use |
|------|-----|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `test:` | Test improvements |
| `docs:` | Documentation |
| `refactor:` | Code restructuring |
| `chore:` | Maintenance |
| `ci:` | CI/CD changes |

### 5. Push and Create PR

```bash
git push origin feat/my-feature
```

Create a pull request on GitHub. CI will automatically run:
- DCO check
- Lint (go vet, gofmt, go mod tidy)
- Tests (non-CGO and CGO)
- Coverage check (≥90% per package)
- Build verification (both CGO modes)
- Docker build

## Adding Detection Patterns

New detection patterns go in `pkg/detectors/`. Each pattern needs:

1. **Pattern definition** with unique `Name`, `Severity`, `Regex`, and `Description`
2. **Tests** in a corresponding `_test.go` file
3. **Rule metadata** (CWE/OWASP) in `pkg/output/rule_metadata.go` — see fallback logic for category-based defaults

Pattern severity levels:

| Severity | Use |
|----------|-----|
| `SeverityCritical` | Code execution, data exfiltration, prompt injection |
| `SeverityHigh` | Secrets, dangerous functions, SSRF |
| `SeverityMedium` | PII, internal URLs, compliance references |
| `SeverityLow` | Informational, minor policy violations |

## Adding Output Formats

New output formats go in `pkg/output/`. Each formatter must:

1. Implement the output function
2. Be registered in the CLI (`cmd/aegisgate-scanner/main.go`)
3. Be added to `--help` text
4. Include tests

## Code Review

All PRs require review. Reviewers check for:

- Correctness of detection logic
- False positive potential
- Test coverage
- Performance impact
- Security (no path traversal, no injection in patterns)

## License

By contributing, you agree that your contributions are licensed under
Apache-2.0.

## Questions?

- Open a [Discussion](https://github.com/aegisgatesecurity/aegisgate-scanner/discussions)
- Email: **dev@aegisgate.ai**