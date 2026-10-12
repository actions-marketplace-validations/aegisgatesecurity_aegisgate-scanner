// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Inline Suppression Support
// =========================================================================
//
// Parses inline suppression comments in source files and filters out
// matching findings. Supports multiple comment styles:
//
//   # aegisgate-ignore: rule_id          (Python, YAML, shell, TOML)
//   // aegisgate-ignore: rule_id         (Go, JS, TS, C, Java)
//   <!-- aegisgate-ignore: rule_id -->   (HTML, XML, Markdown)
//   /* aegisgate-ignore: rule_id */      (CSS, C, multi-line)
//
// Suppression can also use "all" to suppress all findings on the line:
//
//   # aegisgate-ignore: all
//
// A suppression applies to the line it appears on AND the next non-empty
// line (similar to eslint's // eslint-disable-next-line).
//
// =========================================================================

package scanner

import (
	"regexp"
	"strings"
)

// suppressionRegex matches aegisgate-ignore comments in any language style.
// Captures the rule ID (or "all") after the colon.
var suppressionRegex = regexp.MustCompile(
	`aegisgate-ignore:\s*([a-zA-Z0-9_\-]+)`,
)

// Suppression represents a single inline suppression directive.
type Suppression struct {
	RuleID string // rule ID to suppress, or "all"
	Line   int    // line where the suppression comment appears
}

// ParseSuppressions scans content for aegisgate-ignore comments and
// returns the list of suppressions found.
func ParseSuppressions(content string) []Suppression {
	var suppressions []Suppression
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		matches := suppressionRegex.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			if len(m) >= 2 {
				suppressions = append(suppressions, Suppression{
					RuleID: strings.TrimSpace(m[1]),
					Line:   i + 1, // 1-based line number
				})
			}
		}
	}

	return suppressions
}

// ApplySuppressions filters out findings that are suppressed by inline
// comments. A suppression on line N applies to findings on line N and
// line N+1 (the next non-empty line).
func ApplySuppressions(findings []Finding, suppressions []Suppression) []Finding {
	if len(suppressions) == 0 {
		return findings
	}

	// Build a lookup: (ruleID or "all") → set of suppressed lines.
	type suppressKey struct {
		ruleID string
		line   int
	}
	suppressed := make(map[suppressKey]bool)

	for _, s := range suppressions {
		// Suppress the line the comment is on.
		suppressed[suppressKey{s.RuleID, s.Line}] = true
		// Suppress the next line (common pattern: suppression on the
		// line above the finding, like eslint-disable-next-line).
		suppressed[suppressKey{s.RuleID, s.Line + 1}] = true
	}

	var filtered []Finding
	for _, f := range findings {
		// Check if this finding is suppressed.
		// "all" suppressions match any rule ID.
		if suppressed[suppressKey{"all", f.Line}] {
			continue
		}
		if suppressed[suppressKey{f.RuleID, f.Line}] {
			continue
		}
		filtered = append(filtered, f)
	}

	if filtered == nil {
		filtered = []Finding{}
	}

	return filtered
}
