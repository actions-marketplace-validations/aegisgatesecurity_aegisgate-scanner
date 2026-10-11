// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Text Output Formatter
// =========================================================================
//
// Produces human-readable text output suitable for terminal display.
// Color-coded by severity with a summary table at the end.
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
// ANSI color codes
// ---------------------------------------------------------------------

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[0;31m"
	colorYellow = "\033[1;33m"
	colorGreen  = "\033[0;32m"
	colorCyan   = "\033[0;36m"
	colorGray   = "\033[0;90m"
	colorBold   = "\033[1m"
)

// ---------------------------------------------------------------------
// Formatter
// ---------------------------------------------------------------------

// FormatText produces human-readable text output from scan results.
// If color is true, ANSI escape codes are included for terminal display.
func FormatText(result *scanner.ScanResult, root, toolVersion string, color bool) string {
	var sb strings.Builder

	// Header
	if color {
		sb.WriteString(colorBold)
	}
	sb.WriteString("AegisGate Scanner v" + toolVersion + "\n")
	if color {
		sb.WriteString(colorReset)
	}
	sb.WriteString(strings.Repeat("=", 60) + "\n")
	sb.WriteString(fmt.Sprintf("Scanning: %s\n", root))
	sb.WriteString(fmt.Sprintf("Duration: %s\n", result.Duration))
	sb.WriteString("\n")

	// Sort findings by severity (critical first), then by file, then by line.
	sortedFindings := sortFindings(result.Findings)

	// Group findings by file.
	grouped := groupByFile(sortedFindings)

	for _, file := range grouped {
		if color {
			sb.WriteString(colorCyan)
		}
		sb.WriteString(fmt.Sprintf("📄 %s\n", file.path))
		if color {
			sb.WriteString(colorReset)
		}

		for _, f := range file.findings {
			sevStr := string(f.Severity)
			if color {
				sevStr = colorize(f.Severity, sevStr)
			}

			sb.WriteString(fmt.Sprintf("  %s [%s] %s\n",
				sevStr,
				f.DetectionLayer,
				f.Message))
			sb.WriteString(fmt.Sprintf("    → %s:%d:%d\n",
				f.Artifact, f.Line, f.Column))
			if f.MatchedText != "" {
				sb.WriteString(fmt.Sprintf("    match: %s\n",
					truncateText(f.MatchedText, 100)))
			}
			if f.DetectionLayer == "ml" {
				sb.WriteString(fmt.Sprintf("    ml_score: %.4f variant: %s\n",
					f.MLScore, f.MLVariant))
			}
			sb.WriteString("\n")
		}
	}

	// Summary
	sb.WriteString(strings.Repeat("=", 60) + "\n")
	if color {
		sb.WriteString(colorBold)
	}
	sb.WriteString("Summary\n")
	if color {
		sb.WriteString(colorReset)
	}
	sb.WriteString(fmt.Sprintf("  Files scanned:     %d\n", result.Stats.FilesScanned))
	sb.WriteString(fmt.Sprintf("  Files with findings: %d\n", result.Stats.FilesWithFindings))
	sb.WriteString(fmt.Sprintf("  Total findings:    %d\n", result.Stats.TotalFindings))
	sb.WriteString("\n")

	// By severity
	if len(result.Stats.BySeverity) > 0 {
		sb.WriteString("  By severity:\n")
		sevs := []detectors.Severity{
			detectors.SeverityCritical,
			detectors.SeverityHigh,
			detectors.SeverityMedium,
			detectors.SeverityLow,
		}
		for _, sev := range sevs {
			if count, ok := result.Stats.BySeverity[sev]; ok {
				sevStr := string(sev)
				if color {
					sevStr = colorize(sev, sevStr)
				}
				sb.WriteString(fmt.Sprintf("    %s: %d\n", sevStr, count))
			}
		}
	}

	// By category
	if len(result.Stats.ByCategory) > 0 {
		sb.WriteString("\n  By category:\n")
		cats := make([]string, 0, len(result.Stats.ByCategory))
		for cat := range result.Stats.ByCategory {
			cats = append(cats, cat)
		}
		sort.Strings(cats)
		for _, cat := range cats {
			sb.WriteString(fmt.Sprintf("    %s: %d\n", cat, result.Stats.ByCategory[cat]))
		}
	}

	// By detection layer
	if len(result.Stats.ByLayer) > 0 {
		sb.WriteString("\n  By detection layer:\n")
		layers := make([]string, 0, len(result.Stats.ByLayer))
		for layer := range result.Stats.ByLayer {
			layers = append(layers, layer)
		}
		sort.Strings(layers)
		for _, layer := range layers {
			sb.WriteString(fmt.Sprintf("    %s: %d\n", layer, result.Stats.ByLayer[layer]))
		}
	}

	if result.Stats.MLInferences > 0 {
		sb.WriteString(fmt.Sprintf("\n  ML inferences: %d\n", result.Stats.MLInferences))
	}

	// Exit code hint
	sb.WriteString("\n")
	if result.Stats.TotalFindings > 0 {
		if color {
			sb.WriteString(colorRed)
		}
		sb.WriteString(fmt.Sprintf("❌ %d finding(s) detected — scan failed\n", result.Stats.TotalFindings))
		if color {
			sb.WriteString(colorReset)
		}
	} else {
		if color {
			sb.WriteString(colorGreen)
		}
		sb.WriteString("✅ No findings — scan passed\n")
		if color {
			sb.WriteString(colorReset)
		}
	}

	return sb.String()
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// fileFindings groups findings by file path.
type fileFindings struct {
	path     string
	findings []scanner.Finding
}

// groupByFile groups findings by file path, preserving sort order.
func groupByFile(findings []scanner.Finding) []fileFindings {
	groups := make(map[string][]scanner.Finding)
	order := []string{}

	for _, f := range findings {
		if _, exists := groups[f.Artifact]; !exists {
			order = append(order, f.Artifact)
		}
		groups[f.Artifact] = append(groups[f.Artifact], f)
	}

	result := make([]fileFindings, 0, len(order))
	for _, path := range order {
		result = append(result, fileFindings{
			path:     path,
			findings: groups[path],
		})
	}
	return result
}

// sortFindings sorts findings by severity (critical first), then file, then line.
func sortFindings(findings []scanner.Finding) []scanner.Finding {
	sorted := make([]scanner.Finding, len(findings))
	copy(sorted, findings)

	sort.SliceStable(sorted, func(i, j int) bool {
		ri := severityRank(sorted[i].Severity)
		rj := severityRank(sorted[j].Severity)
		if ri != rj {
			return ri > rj // higher severity first
		}
		if sorted[i].Artifact != sorted[j].Artifact {
			return sorted[i].Artifact < sorted[j].Artifact
		}
		return sorted[i].Line < sorted[j].Line
	})

	return sorted
}

// severityRank returns a numeric rank for sorting (higher = more severe).
func severityRank(sev detectors.Severity) int {
	switch sev {
	case detectors.SeverityCritical:
		return 4
	case detectors.SeverityHigh:
		return 3
	case detectors.SeverityMedium:
		return 2
	case detectors.SeverityLow:
		return 1
	default:
		return 0
	}
}

// colorize wraps text in ANSI color codes based on severity.
func colorize(sev detectors.Severity, text string) string {
	switch sev {
	case detectors.SeverityCritical:
		return colorRed + colorBold + text + colorReset
	case detectors.SeverityHigh:
		return colorRed + text + colorReset
	case detectors.SeverityMedium:
		return colorYellow + text + colorReset
	case detectors.SeverityLow:
		return colorGray + text + colorReset
	default:
		return text
	}
}

// truncateText shortens text for display, appending "..." if truncated.
func truncateText(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
