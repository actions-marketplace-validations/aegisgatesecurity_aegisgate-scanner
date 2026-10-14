// SPDX-License-Identifier: Apache-2.0
package scanner

import (
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/detectors"
)

func TestGetRemediation_SpecificRule(t *testing.T) {
	got := getRemediation("secrets", "secret_aws_key", detectors.SeverityCritical)
	if !strings.Contains(got, "AWS") {
		t.Errorf("expected AWS-specific guidance, got: %s", got)
	}
}

func TestGetRemediation_CategoryFallback(t *testing.T) {
	got := getRemediation("pii-us-core", "unknown_rule", detectors.SeverityHigh)
	if !strings.Contains(got, "PII") || !strings.Contains(got, "redact") {
		t.Errorf("expected PII redaction guidance, got: %s", got)
	}
}

func TestGetRemediation_PrefixFallback(t *testing.T) {
	got := getRemediation("custom", "secret_custom_token", detectors.SeverityHigh)
	if !strings.Contains(got, "secret") || !strings.Contains(got, "rotate") {
		t.Errorf("expected secret rotation guidance, got: %s", got)
	}
}

func TestGetRemediation_SeverityDefault(t *testing.T) {
	got := getRemediation("unknown", "unknown_rule", detectors.SeverityCritical)
	if !strings.Contains(got, "CRITICAL") {
		t.Errorf("expected CRITICAL guidance, got: %s", got)
	}
}

func TestGetRemediation_DangerousFunction(t *testing.T) {
	got := getRemediation("dangerous-function", "dangerous_py_eval", detectors.SeverityHigh)
	if !strings.Contains(got, "eval") || !strings.Contains(got, "ast.literal_eval") {
		t.Errorf("expected eval-specific guidance, got: %s", got)
	}
}

func TestScanArtifact_HasRemediation(t *testing.T) {
	art := makeArtifact("test.txt", "AKIAIOSFODNN7EXAMPLE\n")
	s, _ := New(ScanOptions{})
	defer s.Close()

	findings := s.ScanArtifact(art, ScanOptions{})
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	for _, f := range findings {
		if f.Remediation == "" {
			t.Errorf("finding %s has empty Remediation", f.RuleID)
		}
	}
}
