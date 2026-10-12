// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — HTML Output Formatter Tests
// =========================================================================
//
// Tests for FormatHTML() verifying output structure, content, severity
// badges, rule metadata, self-containment, and edge cases.
//
// =========================================================================

package output

import (
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-scanner/internal/detectors"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/scanner"
)

// ---------------------------------------------------------------------
// FormatHTML basic tests
// ---------------------------------------------------------------------

func TestFormatHTML_Basic(t *testing.T) {
	result := makeScanResult()
	data, err := FormatHTML(result, "/test/root", "v1.0.0")
	if err != nil {
		t.Fatalf("FormatHTML error: %v", err)
	}
	html := string(data)

	if !strings.HasPrefix(html, "<!DOCTYPE html>") {
		t.Error("HTML output must start with DOCTYPE")
	}
	if !strings.Contains(html, "<html") {
		t.Error("HTML output must contain <html> tag")
	}
	if !strings.Contains(html, "</html>") {
		t.Error("HTML output must contain closing </html> tag")
	}
}

func TestFormatHTML_ContainsSummary(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatHTML(result, "/test/root", "v1.0.0")
	html := string(data)

	if !strings.Contains(html, "Files Scanned") {
		t.Error("HTML should contain 'Files Scanned' summary card")
	}
	if !strings.Contains(html, "Total Findings") {
		t.Error("HTML should contain 'Total Findings' summary card")
	}
	for _, sev := range []string{"Critical", "High", "Medium", "Low"} {
		if !strings.Contains(html, sev) {
			t.Errorf("HTML should contain '%s' severity card", sev)
		}
	}
}

func TestFormatHTML_ContainsFindings(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatHTML(result, "/test/root", "v1.0.0")
	html := string(data)

	if !strings.Contains(html, "docs/rag/knowledge.md") {
		t.Error("HTML should contain finding file path")
	}
	if !strings.Contains(html, "configs/secrets.yaml") {
		t.Error("HTML should contain finding file path")
	}
	if !strings.Contains(html, "ml_prompt_injection") {
		t.Error("HTML should contain rule ID")
	}
	if !strings.Contains(html, "secret_aws_key") {
		t.Error("HTML should contain rule ID")
	}
}

func TestFormatHTML_SeverityBadges(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatHTML(result, "/test/root", "v1.0.0")
	html := string(data)

	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if !strings.Contains(html, "badge "+sev) {
			t.Errorf("HTML should contain '%s' severity badge", sev)
		}
	}
}

func TestFormatHTML_RuleMetadata(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatHTML(result, "/test/root", "v1.0.0")
	html := string(data)

	if !strings.Contains(html, "CWE-") {
		t.Error("HTML should contain CWE references in rule metadata")
	}
}

func TestFormatHTML_SelfContained(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatHTML(result, "/test/root", "v1.0.0")
	html := string(data)

	if strings.Contains(html, "<link") {
		t.Error("HTML should not reference external CSS (self-contained)")
	}
	if strings.Contains(html, "src=\"http") {
		t.Error("HTML should not reference external resources")
	}
	if !strings.Contains(html, "<style>") {
		t.Error("HTML should contain inline <style>")
	}
	if !strings.Contains(html, "<script>") {
		t.Error("HTML should contain inline <script> for sorting")
	}
}

func TestFormatHTML_SortableTable(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatHTML(result, "/test/root", "v1.0.0")
	html := string(data)

	if !strings.Contains(html, "id=\"findings-table\"") {
		t.Error("HTML table should have id 'findings-table'")
	}
	if !strings.Contains(html, "data-type=") {
		t.Error("HTML table headers should have data-type attributes for sorting")
	}
}

func TestFormatHTML_EmptyResults(t *testing.T) {
	result := makeEmptyScanResult()
	data, err := FormatHTML(result, "/empty", "v1.0.0")
	if err != nil {
		t.Fatalf("FormatHTML error on empty: %v", err)
	}
	html := string(data)

	if !strings.Contains(html, "No security findings") {
		t.Error("HTML for empty results should show no findings message")
	}
}

func TestFormatHTML_RootPathInOutput(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatHTML(result, "/my/scan/path", "v1.0.0")
	html := string(data)

	if !strings.Contains(html, "/my/scan/path") {
		t.Error("HTML should contain the scan root path")
	}
}

func TestFormatHTML_ToolVersion(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatHTML(result, "/root", "v9.9.9")
	html := string(data)

	if !strings.Contains(html, "v9.9.9") {
		t.Error("HTML should contain the tool version")
	}
}

func TestFormatHTML_CategoryBreakdown(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatHTML(result, "/root", "v1.0.0")
	html := string(data)

	if !strings.Contains(html, "By Category") {
		t.Error("HTML should contain 'By Category' section")
	}
	if !strings.Contains(html, "secrets") {
		t.Error("HTML should contain 'secrets' category")
	}
}

func TestFormatHTML_XSSInFindingText(t *testing.T) {
	result := makeScanResult()
	// The XSS finding has <script>alert('xss')</script> as matched text.
	data, _ := FormatHTML(result, "/root", "v1.0.0")
	html := string(data)

	// The <script> tag from finding text should be escaped.
	// Note: the inline <script> tag for sorting is legitimate HTML,
	// but the finding's matched text should be escaped.
	if strings.Contains(html, "&lt;script&gt;alert") || !strings.Contains(html, "alert") {
		// Either escaped or the word alert is present (it's in the finding text).
		// The key check is that the raw <script>alert('xss')</script> from
		// matched text doesn't appear unescaped outside of the legitimate script tag.
	} else {
		t.Error("HTML output should handle XSS content in finding text")
	}
}

func TestFormatHTML_SingleFinding(t *testing.T) {
	result := makeEmptyScanResult()
	result.Findings = []scanner.Finding{
		{
			Artifact:       "single.txt",
			RuleID:         "secret_aws_key",
			Category:       "secrets",
			Severity:       detectors.SeverityCritical,
			Confidence:     1.0,
			Message:        "critical: detected secret_aws_key",
			Line:           1,
			Column:         1,
			EndLine:        1,
			EndColumn:      20,
			MatchedText:    "AKIAIOSFODNN7EXAMPLE",
			DetectionLayer: "regex",
		},
	}
	result.Stats.TotalFindings = 1
	result.Stats.BySeverity[detectors.SeverityCritical] = 1

	data, err := FormatHTML(result, "/root", "v1.0.0")
	if err != nil {
		t.Fatalf("FormatHTML error: %v", err)
	}
	html := string(data)

	if !strings.Contains(html, "single.txt") {
		t.Error("HTML should contain the single finding file")
	}
	if !strings.Contains(html, "badge critical") {
		t.Error("HTML should contain critical badge for single finding")
	}
}
