# Patent Coverage Analysis — AegisGate Scanner

**Date:** October 12, 2026
**Author:** Engineering
**Status:** REQUIRES LEGAL REVIEW

## Provisional Patents Filed

| App. No. | Filed | Title (assumed) |
|----------|-------|-----------------|
| 64/153,573 | Sep 12, 2026 | AI threat detection (Rampart proxy) |
| 64/153,574 | Sep 12, 2026 | ML-based prompt injection detection |
| 64/153,575 | Sep 12, 2026 | Text normalization for adversarial evasion |
| 64/153,576 | Sep 12, 2026 | MCP server security framework |
| 64/153,577 | Sep 12, 2026 | (Unknown — possibly Platform gateway) |

## Scanner Novel Aspects

### Potentially Covered by Existing Provisionals
1. **CharCNN-BiLSTM ML detection** — likely covered by 64/153,574 (ML prompt injection)
2. **Text normalization / adversarial evasion resistance** — likely covered by 64/153,575
3. **Regex + ML two-layer detection pipeline** — may be covered by 64/153,573

### Potentially NOT Covered (New Invention)
4. **Static analysis of AI training artifacts for security threats** — applying SAST techniques to AI supply chain inputs (RAG docs, training data, agent skills). This is a novel application domain not addressed by existing SAST tools or the provisionals.
5. **AI artifact classification taxonomy** — 10-category threat model specific to AI artifacts (prompt injection in RAG, dangerous functions in agent skills, OT protocol exposure in training data)
6. **Archive extraction + scanning pipeline for AI artifacts** — extracting and scanning inside archives with bomb/traversal protection, specifically for AI supply chain inputs
7. **Baseline suppression for artifact scanning** — diff-based finding suppression for CI/CD gating on AI artifacts

## Risk Assessment

**Scanner was built October 2026, AFTER the September 12 provisionals.**
Scanner is now public (open source on GitHub).

- If Scanner's novel aspects ARE covered by existing provisionals → safe, convert to utility within 12 months
- If Scanner's novel aspects are NOT covered → **public disclosure bar risk**
  - US: 1-year grace period (file by October 2027)
  - EU: NO grace period (absolute novelty required — may already be barred)
  - Recommendation: File new provisional ASAP

## Recommended Actions

1. **Schedule call with patent counsel** to review whether Scanner's method claims fall within the scope of 64/153,573–64/153,577
2. **If not covered:** File new provisional application covering:
   - "Method and system for static analysis of AI training artifacts for security threats"
   - Claims: artifact classification, regex+ML detection pipeline, archive extraction, baseline suppression, SARIF/SBOM generation for AI artifacts
3. **Document invention dates** — Git commits serve as evidence of conception and reduction to practice
4. **Do not publish detailed technical papers** about Scanner's novel detection method until patent strategy is confirmed