# GitHub Discussions — AegisGate Scanner

This directory contains the first three GitHub Discussion templates to
seed the community. After enabling Discussions in repo settings
(Settings → General → Features → Discussions), create these as
discussions in the "Ideas" and "Q&A" categories.

---

## Discussion 1: Ideas 💡

### Title: What artifacts should Scanner scan?

**Body:**

We built AegisGate Scanner to detect security threats in AI artifacts — RAG documents, training data, model configs, and agent skills. But we want to hear from you:

- **What file types are in your AI artifact pipeline?** (`.jsonl`, `.parquet`, `.csv`, `.md`, `.py`, `.yaml`, something else?)
- **What directories do you store artifacts in?** (`data/`, `rag/`, `training/`, `agent_skills/`, `models/`?)
- **Are there file types Scanner should support but currently doesn't?**

Currently Scanner supports: `.csv`, `.htm`, `.html`, `.js`, `.json`, `.jsonl`, `.md`, `.py`, `.rst`, `.toml`, `.ts`, `.tsv`, `.txt`, `.xml`, `.yaml`, `.yml`

Your input directly shapes our default extension list and ignore patterns. Drop a comment with your stack 👇

---

## Discussion 2: Ideas 💡

### Title: Pattern requests — what should we detect?

**Body:**

Scanner currently has 257 detection patterns across 10 categories:

| Category | Count |
|----------|-------|
| Prompt Injection | 12 |
| Secrets | 65 |
| PII (US Core) | 32 |
| PII (US Extended) | 13 |
| PII (Financial) | 16 |
| PII (International) | 24 |
| XSS | 12 |
| Compliance | 35 |
| Dangerous Functions | 34 |
| OT/ICS Protocols | 9 |

But we know there are more AI-specific threats out there. **What patterns should we add?**

Examples we're considering:
- Model poisoning indicators (backdoored weights, trigger words)
- Data exfiltration patterns (covert channels, steganography)
- Agent skill sandbox escapes (privileged API calls, file system access)
- Fine-tuning data manipulation (label flipping, gradient hacking)
- RAG retrieval poisoning (crafted passages designed to influence LLM output)

Share examples of threats you've seen in the wild. We'll triage and add the best ones to the pattern library. Format:

```
**Pattern name:** e.g., "model_poisoning_trigger_word"
**Regex:** (if you have one)
**Severity:** critical / high / medium / low
**Description:** What it detects and why it matters
**Example:** A sample (redacted) payload that should trigger
```

---

## Discussion 3: Q&A ❓

### Title: Scanner performance — share your scan times

**Body:**

We've optimized Scanner's performance significantly (3x speedup in v0.1.0), but we want real-world data. **Share your scan metrics:**

```
**Repo size:** e.g., 50 MB, 1,200 files
**File types:** e.g., .py, .json, .md
**Concurrency:** e.g., 4
**ML enabled:** yes / no
**Scan time:** e.g., 12.3 seconds
**Findings:** e.g., 45 (5 high, 20 medium, 20 low)
**Hardware:** e.g., GitHub Actions ubuntu-latest, M2 MacBook Pro
```

This helps us:
1. Identify performance bottlenecks in real workloads
2. Set realistic CI/CD time expectations for users
3. Prioritize optimization efforts

Current benchmark (Intel Xeon E5-2687W v3, 40 cores):

| File Size | Scan Time | Findings |
|-----------|-----------|----------|
| 1 KB | 18 ms | ~5 |
| 100 KB | 1.2 s | ~50 |
| 1 MB | 12.7 s | ~500 |

We're working on alternation regex compilation (257→1 pass) for a further 10x improvement. Stay tuned.