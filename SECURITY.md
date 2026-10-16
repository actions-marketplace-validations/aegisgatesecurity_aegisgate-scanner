# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AegisGate Scanner, please
report it responsibly.

### How to Report

1. **DO NOT** open a public GitHub issue.
2. Email: **security@aegisgate.ai**
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

| Step | Target |
|------|--------|
| Acknowledgment | 48 hours |
| Initial assessment | 5 business days |
| Fix or mitigation | 30 days (severity-dependent) |
| Public disclosure | After fix is released |

### Scope

- AegisGate Scanner (this repository)
- Detection bypass vulnerabilities (patterns that fail to detect known threats)
- False positive/negative issues with security implications
- Supply chain risks in dependencies

### Out of Scope

- Vulnerabilities in third-party dependencies (report upstream)
- Issues in the AegisGate Platform product (separate disclosure process)
- Social engineering attacks

### PGP

For sensitive reports, encrypt to:

```
AegisGate Security Team <security@aegisgate.ai>
```

(Contact us via email for the current public key fingerprint.)

## Security Features

AegisGate Scanner includes built-in security measures:

- **Path traversal protection** in archive extraction (Zip Slip / Tar Slip prevention)
- **Symlink loop detection** during directory walks
- **File size limits** to prevent resource exhaustion
- **No network calls** during scanning (air-gapped capable)
- **No telemetry** — the scanner does not phone home

## Acknowledgments

Responsible disclosure reporters will be credited here (with permission)
after the vulnerability is fixed.

### Community Contributions

We thank the following community members for thought-sharing, pattern
suggestions, and security insights that have improved AegisGate Scanner:

- **[@redbotster](https://github.com/redbotster)** (1claw) — Field-validated
  pattern suggestions for indirect prompt injection via tool outputs,
  token smuggling with zero-width unicode, short-lived credential formats,
  and agent sandbox escape vectors (path traversal, sensitive file access).
  These contributions directly informed the path traversal and sensitive
  file access detection patterns added in v0.5.0. See [Discussion #8](https://github.com/aegisgatesecurity/aegisgate-scanner/discussions/8).