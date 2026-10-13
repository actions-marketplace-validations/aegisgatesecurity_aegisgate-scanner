# Patent Coverage Analysis — AegisGate Scanner

**Date:** October 12, 2026
**Author:** Engineering
**Status:** REQUIRES LEGAL REVIEW

## Provisional Patents Filed

| App. No. | Filed | Title |
|----------|-------|-------|
| 64/153,573 | Sep 12, 2026 | Trust Framework — cryptographic identity, capability contracts, trust scoring, attestations |
| 64/153,574 | Sep 12, 2026 | Multi-Protocol Interception — MCP/A2A/ACP/ANP scanning for data exfiltration |
| 64/153,575 | Sep 12, 2026 | Compliance Mapping — mapping AI detections to 31+ compliance framework controls |
| 64/153,576 | Sep 12, 2026 | Three-Layer Detection Pipeline — regex then ATLAS/compliance then CharCNN-BiLSTM |
| 64/153,577 | Sep 12, 2026 | Response Scanning — scanning AI model outputs for PII, secrets, hallucinations, toxicity |
| 64/174,824 | Oct 12, 2026 | **THIS APPLICATION** — Static Analysis of AI Training Artifacts for Security Threats |

## Scanner (6th Application) — Novel Aspects

### Potentially Covered by Existing Provisionals
1. **CharCNN-BiLSTM ML detection** — likely covered by 64/153,576 (3-Layer Detection Pipeline)
2. **Text normalization / adversarial evasion resistance** — likely covered by 64/153,576 (3-Layer Detection Pipeline)
3. **Regex + ML two-layer detection pipeline** — likely covered by 64/153,576 (3-Layer Detection Pipeline)
4. **Compliance mapping** — likely covered by 64/153,575 (Compliance Mapping)

### Potentially NOT Covered (New Invention)
5. **Static analysis of AI training artifacts for security threats** — applying SAST techniques to AI supply chain inputs (RAG docs, training data, agent skills). This is a novel application domain not addressed by existing SAST tools or the provisionals.
6. **AI artifact classification taxonomy** — 9-category threat model specific to AI artifacts (prompt injection in RAG, dangerous functions in agent skills, OT protocol exposure in training data)
7. **Archive extraction + scanning pipeline for AI artifacts** — extracting and scanning inside archives with bomb/traversal protection, specifically for AI supply chain inputs
8. **Baseline suppression for artifact scanning** — diff-based finding suppression for CI/CD gating on AI artifacts
9. **Content-addressed result caching** — SHA-256 keyed cache with pattern-set invalidation and LRU/age-based eviction
10. **Line-by-line keyword pre-filtering with O(log n) line lookup** — dual-mode scanning optimized for large artifacts

## Risk Assessment

**Scanner was built October 2026, AFTER the September 12 provisionals.**
Scanner is not yet public (pre-release, patent filing in progress).

- If Scanner's novel aspects ARE covered by existing provisionals → safe, convert to utility within 12 months
- If Scanner's novel aspects are NOT covered → **public disclosure bar risk**
  - US: 1-year grace period (file by October 2027)
  - EU: NO grace period (absolute novelty required — may already be barred)
  - Recommendation: File new provisional ASAP (before GitHub publication)

## Recommended Actions

1. **File provisional patent #6** — ✅ FILED October 12, 2026. App. No. 64/174,824. Confirmation #9820. $65 micro entity fee paid.
2. **File BEFORE pushing to GitHub** — ✅ Patent filed. Clear to push to GitHub.
3. **Document invention dates** — Git commits serve as evidence of conception and reduction to practice
4. **Non-provisional deadline:** September 12, 2027 (for provisionals 1-5), October 12, 2027 (for provisional 6)
5. **Do not publish detailed technical papers** about Scanner's novel detection method — patent now filed, safe to publish