// SPDX-License-Identifier: Apache-2.0
// Tests for JSONL output formatter.

package output

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-scanner/internal/detectors"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/artifacts"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/scanner"
)

func TestFormatJSONL_Basic(t *testing.T) {
	result := &scanner.ScanResult{
		Findings: []scanner.Finding{
			{
				Artifact:       "test.py",
				ArtifactClass:  artifacts.ClassAgentSkill,
				RuleID:         "dangerous_py_eval",
				Category:       "dangerous_functions",
				Severity:       detectors.SeverityCritical,
				Confidence:     1.0,
				Message:        "Use of eval() detected",
				Line:           10,
				Column:         1,
				EndLine:        10,
				EndColumn:      15,
				MatchedText:    "eval(user_input)",
				DetectionLayer: "regex",
				Remediation:    "Replace eval() with ast.literal_eval()",
			},
			{
				Artifact:       "config.yaml",
				ArtifactClass:  artifacts.ClassModelConfig,
				RuleID:         "secret_aws_key",
				Category:       "secrets",
				Severity:       detectors.SeverityHigh,
				Confidence:     0.95,
				Message:        "AWS access key detected",
				Line:           5,
				Column:         1,
				EndLine:        5,
				EndColumn:      20,
				MatchedText:    "AKIAIOSFODNN7EXAMPLE",
				DetectionLayer: "regex",
			},
		},
		Stats: scanner.ScanStats{
			FilesScanned:      2,
			FilesWithFindings: 2,
			TotalFindings:     2,
			BySeverity: map[detectors.Severity]int{
				detectors.SeverityCritical: 1,
				detectors.SeverityHigh:     1,
			},
			ByCategory: map[string]int{
				"dangerous_functions": 1,
				"secrets":             1,
			},
			ByLayer: map[string]int{
				"regex": 2,
			},
		},
		Duration: 100 * time.Millisecond,
	}

	data, err := FormatJSONL(result, "/test", "0.1.0")
	if err != nil {
		t.Fatalf("FormatJSONL failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	// 2 findings + 1 summary = 3 lines
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}

	// Verify each line is valid JSON.
	for i, line := range lines {
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("line %d is not valid JSON: %v (line: %s)", i, err, line)
		}
	}

	// First two lines should be findings.
	for i := 0; i < 2; i++ {
		var obj map[string]interface{}
		json.Unmarshal([]byte(lines[i]), &obj)
		if obj["type"] != "finding" {
			t.Errorf("line %d: expected type=finding, got %v", i, obj["type"])
		}
	}

	// Last line should be summary.
	var summary map[string]interface{}
	json.Unmarshal([]byte(lines[2]), &summary)
	if summary["type"] != "summary" {
		t.Errorf("last line: expected type=summary, got %v", summary["type"])
	}
	if summary["tool"] != "aegisgate-scanner" {
		t.Errorf("summary tool: expected aegisgate-scanner, got %v", summary["tool"])
	}
}

func TestFormatJSONL_NoFindings(t *testing.T) {
	result := &scanner.ScanResult{
		Findings: []scanner.Finding{},
		Stats: scanner.ScanStats{
			FilesScanned:  5,
			TotalFindings: 0,
		},
		Duration: 50 * time.Millisecond,
	}

	data, err := FormatJSONL(result, "/clean", "0.1.0")
	if err != nil {
		t.Fatalf("FormatJSONL failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	// 0 findings + 1 summary = 1 line
	if len(lines) != 1 {
		t.Fatalf("expected 1 line (summary only), got %d", len(lines))
	}

	var summary map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &summary); err != nil {
		t.Fatalf("summary line is not valid JSON: %v", err)
	}
	if summary["type"] != "summary" {
		t.Errorf("expected type=summary, got %v", summary["type"])
	}
}

func TestFormatJSONL_MLFindingFields(t *testing.T) {
	result := &scanner.ScanResult{
		Findings: []scanner.Finding{
			{
				Artifact:       "prompt.txt",
				ArtifactClass:  artifacts.ClassRAGDocument,
				RuleID:         "ml_prompt_injection",
				Category:       "compliance",
				Severity:       detectors.SeverityHigh,
				Confidence:     0.92,
				Message:        "ML detected prompt injection",
				Line:           1,
				DetectionLayer: "ml",
				MLScore:        0.92,
				MLVariant:      "char_substitution",
			},
		},
		Stats: scanner.ScanStats{
			FilesScanned:      1,
			FilesWithFindings: 1,
			TotalFindings:     1,
			MLInferences:      1,
			ByLayer: map[string]int{
				"ml": 1,
			},
		},
		Duration: 30 * time.Millisecond,
	}

	data, err := FormatJSONL(result, "/test", "0.1.0")
	if err != nil {
		t.Fatalf("FormatJSONL failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (1 finding + 1 summary), got %d", len(lines))
	}

	var finding map[string]interface{}
	json.Unmarshal([]byte(lines[0]), &finding)
	if finding["detection_layer"] != "ml" {
		t.Errorf("expected detection_layer=ml, got %v", finding["detection_layer"])
	}
	if finding["ml_score"] != 0.92 {
		t.Errorf("expected ml_score=0.92, got %v", finding["ml_score"])
	}
	if finding["ml_variant"] != "char_substitution" {
		t.Errorf("expected ml_variant=char_substitution, got %v", finding["ml_variant"])
	}
}

func TestFormatJSONL_SingleLinePerObject(t *testing.T) {
	result := &scanner.ScanResult{
		Findings: []scanner.Finding{
			{
				Artifact:       "a.py",
				RuleID:         "test_rule",
				Category:       "test",
				Severity:       detectors.SeverityLow,
				Message:        "test",
				DetectionLayer: "regex",
			},
		},
		Stats: scanner.ScanStats{
			TotalFindings: 1,
		},
		Duration: 10 * time.Millisecond,
	}

	data, err := FormatJSONL(result, "/test", "0.1.0")
	if err != nil {
		t.Fatalf("FormatJSONL failed: %v", err)
	}

	// Each line must be a single line (no embedded newlines).
	for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.Contains(line, "\n") {
			t.Errorf("line %d contains embedded newline", i)
		}
	}
}
