# Changelog

All notable changes to AegisGate Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial repository structure
- Detection engine ported from AegisGate Rampart (223 regex patterns)
- ML threat detection stack ported from AegisGate MCP (CharCNN-BiLSTM v13)
- Evasion-resistant text normalization (homoglyph, l33t, zero-width, Unicode)
- PII detection (US core, US extended, financial, international)
- Secret detection (65 credential patterns)
- XSS detection (11 patterns)
- OT/ICS protocol detection (10 patterns)
- Compliance pattern detection (35 patterns)
- Zero external module dependencies (all third-party code vendored)
- Dual build modes: CGO (neural) and non-CGO (heuristic-only)
- Apache 2.0 license
- DCO enforcement
- OPSEC pre-commit hooks