// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — PR Annotation Output Formatter
// =========================================================================
//
// Generates GitHub PR comments in markdown format and GitHub Actions
// workflow commands for inline annotations.
//
// Output formats:
//   - pr-comment: Markdown summary suitable for `gh pr comment` or
//     posting as a PR review comment. Includes a summary line with
//     finding count, a table grouped by severity, and collapsible
//     details for each finding.
//   - github-actions: GitHub Actions workflow command syntax
//     (::error, ::warning, ::notice) for inline annotations in PR
//     diffs.
//
// =========================================================================

package output

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aegisgatesecurity/aegisgate-scanner/internal/detectors"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/scanner"
)

// ---------------------------------------------------------------------
// PR Comment format (Markdown)
// ---------------------------------------------------------------------

// FormatPRComment produces a GitHub PR comment in markdown format.
// The output includes a summary header, a table grouped by severity,
// and collapsible <details> sections for each finding.
func FormatPRComment(result *scanner.ScanResult, root, toolVersion string) ([]byte, error) {
	var sb strings.Builder

	// Summary header.
	sb.WriteString(fmt.Sprintf("## 🛡️ AegisGate Scanner Report\n\n"))
	sb.WriteString(fmt.Sprintf("**Scan root:** `%s`  \n", root))
	sb.WriteString(fmt.Sprintf("**Tool version:** %s  \n", toolVersion))
	sb.WriteString(fmt.Sprintf("**Duration:** %s  \n\n", result.Duration))

	if result.Stats.TotalFindings == 0 {
		sb.WriteString("✅ **No security findings detected.** Scan passed.\n")
		return []byte(sb.String()), nil
	}

	// Summary line.
	sb.WriteString(fmt.Sprintf("⚠️ **%d finding(s) detected** across %d file(s).\n\n",
		result.Stats.TotalFindings, result.Stats.FilesWithFindings))

	// Severity counts table.
	sb.WriteString("### Summary by Severity\n\n")
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")

	sevs := []detectors.Severity{
		detectors.SeverityCritical,
		detectors.SeverityHigh,
		detectors.SeverityMedium,
		detectors.SeverityLow,
	}
	sevEmoji := map[detectors.Severity]string{
		detectors.SeverityCritical: "🔴",
		detectors.SeverityHigh:     "🟠",
		detectors.SeverityMedium:   "🟡",
		detectors.SeverityLow:      "🔵",
	}
	for _, sev := range sevs {
		count := result.Stats.BySeverity[sev]
		if count > 0 {
			sb.WriteString(fmt.Sprintf("| %s %s | %d |\n", sevEmoji[sev], string(sev), count))
		}
	}
	sb.WriteString("\n")

	// Category counts table.
	if len(result.Stats.ByCategory) > 0 {
		sb.WriteString("### Summary by Category\n\n")
		sb.WriteString("| Category | Count |\n")
		sb.WriteString("|----------|-------|\n")
		cats := make([]string, 0, len(result.Stats.ByCategory))
		for cat := range result.Stats.ByCategory {
			cats = append(cats, cat)
		}
		sort.Strings(cats)
		for _, cat := range cats {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", cat, result.Stats.ByCategory[cat]))
		}
		sb.WriteString("\n")
	}

	// Findings grouped by severity with collapsible details.
	sorted := sortFindings(result.Findings)
	grouped := groupBySeverity(sorted)

	for _, sev := range sevs {
		findings, ok := grouped[sev]
		if !ok || len(findings) == 0 {
			continue
		}

		sb.WriteString(fmt.Sprintf("<details>\n<summary>%s %s (%d)</summary>\n\n",
			sevEmoji[sev], string(sev), len(findings)))
		sb.WriteString("| File | Line | Rule | Message |\n")
		sb.WriteString("|------|------|------|---------|\n")
		for _, f := range findings {
			sb.WriteString(fmt.Sprintf("| `%s` | %d:%d | `%s` | %s |\n",
				f.Artifact, f.Line, f.Column, f.RuleID, f.Message))
		}

		// Detailed entries.
		sb.WriteString("\n")
		for _, f := range findings {
			sb.WriteString(fmt.Sprintf("**`%s:%d:%d`** — %s\n\n", f.Artifact, f.Line, f.Column, f.RuleID))
			sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", string(f.Severity)))
			sb.WriteString(fmt.Sprintf("- **Category:** %s\n", f.Category))
			sb.WriteString(fmt.Sprintf("- **Message:** %s\n", f.Message))
			if f.MatchedText != "" {
				truncated := truncateText(f.MatchedText, 100)
				sb.WriteString(fmt.Sprintf("- **Match:** `%s`\n", truncated))
			}
			meta := GetRuleMetadataWithDefault(f.RuleID)
			if len(meta.CWE) > 0 {
				cwes := make([]string, len(meta.CWE))
				for i, c := range meta.CWE {
					cwes[i] = fmt.Sprintf("[CWE-%d](https://cwe.mitre.org/data/definitions/%d.html)", c, c)
				}
				sb.WriteString(fmt.Sprintf("- **CWE:** %s\n", strings.Join(cwes, ", ")))
			}
			if meta.OWASPLLMTop != "" {
				sb.WriteString(fmt.Sprintf("- **OWASP LLM Top 10:** %s\n", meta.OWASPLLMTop))
			}
			sb.WriteString("\n")
		}
		sb.WriteString("</details>\n\n")
	}

	// Footer.
	sb.WriteString("---\n_Generated by [AegisGate Scanner](https://aegisgatesecurity.io)_\n")

	return []byte(sb.String()), nil
}

// groupBySeverity groups findings by severity level.
func groupBySeverity(findings []scanner.Finding) map[detectors.Severity][]scanner.Finding {
	groups := make(map[detectors.Severity][]scanner.Finding)
	for _, f := range findings {
		groups[f.Severity] = append(groups[f.Severity], f)
	}
	return groups
}

// ---------------------------------------------------------------------
// GitHub Actions format (workflow commands)
// ---------------------------------------------------------------------

// FormatGitHubActions produces GitHub Actions workflow command
// annotations using ::error, ::warning, and ::notice syntax.
// Each finding is emitted as a separate command for inline annotation
// in the PR diff view.
func FormatGitHubActions(result *scanner.ScanResult, root, toolVersion string) ([]byte, error) {
	var sb strings.Builder

	// Print summary as a group.
	sb.WriteString("::group::AegisGate Scanner Results\n")
	sb.WriteString(fmt.Sprintf("Tool: aegisgate-scanner %s\n", toolVersion))
	sb.WriteString(fmt.Sprintf("Files scanned: %d\n", result.Stats.FilesScanned))
	sb.WriteString(fmt.Sprintf("Total findings: %d\n\n", result.Stats.TotalFindings))

	// Severity summary.
	sevs := []detectors.Severity{
		detectors.SeverityCritical,
		detectors.SeverityHigh,
		detectors.SeverityMedium,
		detectors.SeverityLow,
	}
	for _, sev := range sevs {
		count := result.Stats.BySeverity[sev]
		if count > 0 {
			sb.WriteString(fmt.Sprintf("%s: %d\n", string(sev), count))
		}
	}
	sb.WriteString("::endgroup::\n\n")

	// Emit each finding as a workflow command.
	sorted := sortFindings(result.Findings)
	for _, f := range sorted {
		cmd := severityToGACommand(f.Severity)
		msg := fmt.Sprintf("%s: %s", f.RuleID, f.Message)

		// Escape message for workflow command (newlines and pipes).
		msg = strings.ReplaceAll(msg, "\n", "%0A")
		msg = strings.ReplaceAll(msg, "|", "%7C")

		sb.WriteString(fmt.Sprintf("::%s file=%s,line=%d::%s\n",
			cmd, f.Artifact, f.Line, msg))
	}

	return []byte(sb.String()), nil
}

// severityToGACommand maps AegisGate severity to GitHub Actions command.
func severityToGACommand(sev detectors.Severity) string {
	switch sev {
	case detectors.SeverityCritical, detectors.SeverityHigh:
		return "error"
	case detectors.SeverityMedium:
		return "warning"
	case detectors.SeverityLow:
		return "notice"
	default:
		return "warning"
	}
}
