// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — PR Annotation Tests
// =========================================================================
//
// Tests for FormatPRComment() and FormatGitHubActions() verifying
// markdown structure, severity grouping, workflow commands, and edge cases.
//
// =========================================================================

package output

import (
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/detectors"
)

// ---------------------------------------------------------------------
// FormatPRComment tests
// ---------------------------------------------------------------------

func TestFormatPRComment_Basic(t *testing.T) {
	result := makeScanResult()
	data, err := FormatPRComment(result, "/test/root", "v1.0.0")
	if err != nil {
		t.Fatalf("FormatPRComment error: %v", err)
	}
	md := string(data)

	if !strings.HasPrefix(md, "## 🛡️") {
		t.Error("PR comment should start with markdown header")
	}
}

func TestFormatPRComment_FindingCount(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatPRComment(result, "/root", "v1.0.0")
	md := string(data)

	if !strings.Contains(md, "finding(s) detected") {
		t.Error("PR comment should contain finding count")
	}
	if !strings.Contains(md, "8 finding(s)") {
		t.Errorf("PR comment should contain 8 findings, got: %s", md)
	}
}

func TestFormatPRComment_SeverityTable(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatPRComment(result, "/root", "v1.0.0")
	md := string(data)

	if !strings.Contains(md, "Summary by Severity") {
		t.Error("PR comment should contain severity summary table")
	}
	if !strings.Contains(md, "critical") {
		t.Error("PR comment should contain critical severity")
	}
	if !strings.Contains(md, "high") {
		t.Error("PR comment should contain high severity")
	}
}

func TestFormatPRComment_CategoryTable(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatPRComment(result, "/root", "v1.0.0")
	md := string(data)

	if !strings.Contains(md, "Summary by Category") {
		t.Error("PR comment should contain category summary table")
	}
}

func TestFormatPRComment_CollapsibleDetails(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatPRComment(result, "/root", "v1.0.0")
	md := string(data)

	if !strings.Contains(md, "<details>") {
		t.Error("PR comment should contain collapsible details sections")
	}
	if !strings.Contains(md, "</details>") {
		t.Error("PR comment should close collapsible details sections")
	}
	if !strings.Contains(md, "<summary>") {
		t.Error("PR comment should contain summary tags in collapsible sections")
	}
}

func TestFormatPRComment_RuleMetadata(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatPRComment(result, "/root", "v1.0.0")
	md := string(data)

	if !strings.Contains(md, "CWE") {
		t.Error("PR comment should contain CWE references")
	}
}

func TestFormatPRComment_EmptyResults(t *testing.T) {
	result := makeEmptyScanResult()
	data, err := FormatPRComment(result, "/empty", "v1.0.0")
	if err != nil {
		t.Fatalf("FormatPRComment error on empty: %v", err)
	}
	md := string(data)

	if !strings.Contains(md, "No security findings") {
		t.Error("PR comment for empty results should show no findings")
	}
	if strings.Contains(md, "finding(s) detected") {
		t.Error("PR comment for empty results should not show finding count")
	}
}

func TestFormatPRComment_RootPath(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatPRComment(result, "/my/project", "v1.0.0")
	md := string(data)

	if !strings.Contains(md, "/my/project") {
		t.Error("PR comment should contain scan root path")
	}
}

func TestFormatPRComment_ToolVersion(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatPRComment(result, "/root", "v2.0.0")
	md := string(data)

	if !strings.Contains(md, "v2.0.0") {
		t.Error("PR comment should contain tool version")
	}
}

func TestFormatPRComment_FindingsTable(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatPRComment(result, "/root", "v1.0.0")
	md := string(data)

	// Each finding should have file and line in the table.
	if !strings.Contains(md, "docs/rag/knowledge.md") {
		t.Error("PR comment should contain finding file path")
	}
	if !strings.Contains(md, "secret_aws_key") {
		t.Error("PR comment should contain rule ID in findings table")
	}
}

// ---------------------------------------------------------------------
// FormatGitHubActions tests
// ---------------------------------------------------------------------

func TestFormatGitHubActions_Basic(t *testing.T) {
	result := makeScanResult()
	data, err := FormatGitHubActions(result, "/test/root", "v1.0.0")
	if err != nil {
		t.Fatalf("FormatGitHubActions error: %v", err)
	}
	out := string(data)

	if !strings.Contains(out, "::group::") {
		t.Error("GitHub Actions output should use ::group:: command")
	}
	if !strings.Contains(out, "::endgroup::") {
		t.Error("GitHub Actions output should close group with ::endgroup::")
	}
}

func TestFormatGitHubActions_ErrorCommands(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatGitHubActions(result, "/root", "v1.0.0")
	out := string(data)

	// Critical and high findings should produce ::error commands.
	if !strings.Contains(out, "::error file=") {
		t.Error("GitHub Actions output should contain ::error commands for critical/high")
	}
}

func TestFormatGitHubActions_WarningCommands(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatGitHubActions(result, "/root", "v1.0.0")
	out := string(data)

	// Medium findings should produce ::warning commands.
	if !strings.Contains(out, "::warning file=") {
		t.Error("GitHub Actions output should contain ::warning commands for medium")
	}
}

func TestFormatGitHubActions_NoticeCommands(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatGitHubActions(result, "/root", "v1.0.0")
	out := string(data)

	// Low findings should produce ::notice commands.
	if !strings.Contains(out, "::notice file=") {
		t.Error("GitHub Actions output should contain ::notice commands for low")
	}
}

func TestFormatGitHubActions_FileAndLine(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatGitHubActions(result, "/root", "v1.0.0")
	out := string(data)

	// Should contain file and line annotations.
	if !strings.Contains(out, "line=") {
		t.Error("GitHub Actions output should contain line= annotations")
	}
	if !strings.Contains(out, "file=") {
		t.Error("GitHub Actions output should contain file= annotations")
	}
}

func TestFormatGitHubActions_EmptyResults(t *testing.T) {
	result := makeEmptyScanResult()
	data, err := FormatGitHubActions(result, "/empty", "v1.0.0")
	if err != nil {
		t.Fatalf("FormatGitHubActions error on empty: %v", err)
	}
	out := string(data)

	// Should still have the group header.
	if !strings.Contains(out, "::group::") {
		t.Error("GitHub Actions output for empty should still have group header")
	}
	if strings.Contains(out, "::error file=") {
		t.Error("GitHub Actions output for empty should not have error commands")
	}
}

func TestFormatGitHubActions_ToolVersion(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatGitHubActions(result, "/root", "v3.0.0")
	out := string(data)

	if !strings.Contains(out, "v3.0.0") {
		t.Error("GitHub Actions output should contain tool version")
	}
}

func TestFormatGitHubActions_SeverityCounts(t *testing.T) {
	result := makeScanResult()
	data, _ := FormatGitHubActions(result, "/root", "v1.0.0")
	out := string(data)

	// Should contain severity counts in the group.
	if !strings.Contains(out, "critical:") {
		t.Error("GitHub Actions output should show critical count in summary")
	}
}

func TestSeverityToGACommand(t *testing.T) {
	tests := []struct {
		sev    detectors.Severity
		expect string
	}{
		{detectors.SeverityCritical, "error"},
		{detectors.SeverityHigh, "error"},
		{detectors.SeverityMedium, "warning"},
		{detectors.SeverityLow, "notice"},
		{detectors.Severity(""), "warning"},
	}

	for _, tt := range tests {
		got := severityToGACommand(tt.sev)
		if got != tt.expect {
			t.Errorf("severityToGACommand(%s) = %s, want %s", tt.sev, got, tt.expect)
		}
	}
}
