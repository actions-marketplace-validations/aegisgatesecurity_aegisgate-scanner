// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"testing"
)

func TestParseSuppressions_PythonStyle(t *testing.T) {
	content := `# aegisgate-ignore: secret_aws_key
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
`
	sups := ParseSuppressions(content)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(sups))
	}
	if sups[0].RuleID != "secret_aws_key" {
		t.Errorf("expected rule ID 'secret_aws_key', got '%s'", sups[0].RuleID)
	}
	if sups[0].Line != 1 {
		t.Errorf("expected line 1, got %d", sups[0].Line)
	}
}

func TestParseSuppressions_JSStyle(t *testing.T) {
	content := `const key = "AKIAIOSFODNN7EXAMPLE"; // aegisgate-ignore: secret_aws_key
`
	sups := ParseSuppressions(content)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(sups))
	}
	if sups[0].RuleID != "secret_aws_key" {
		t.Errorf("expected rule ID 'secret_aws_key', got '%s'", sups[0].RuleID)
	}
}

func TestParseSuppressions_HTMLStyle(t *testing.T) {
	content := `<!-- aegisgate-ignore: pii_ssn -->
<p>SSN: 123-45-6789</p>
`
	sups := ParseSuppressions(content)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(sups))
	}
}

func TestParseSuppressions_AllKeyword(t *testing.T) {
	content := `# aegisgate-ignore: all
some content
`
	sups := ParseSuppressions(content)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(sups))
	}
	if sups[0].RuleID != "all" {
		t.Errorf("expected rule ID 'all', got '%s'", sups[0].RuleID)
	}
}

func TestParseSuppressions_MultipleInFile(t *testing.T) {
	content := `# aegisgate-ignore: secret_aws_key
key1 = "AKIAIOSFODNN7EXAMPLE"
# aegisgate-ignore: pii_ssn
ssn = "123-45-6789"
`
	sups := ParseSuppressions(content)
	if len(sups) != 2 {
		t.Fatalf("expected 2 suppressions, got %d", len(sups))
	}
}

func TestParseSuppressions_NoSuppressions(t *testing.T) {
	content := `just some regular code
no suppressions here
`
	sups := ParseSuppressions(content)
	if len(sups) != 0 {
		t.Fatalf("expected 0 suppressions, got %d", len(sups))
	}
}

func TestApplySuppressions_SpecificRule(t *testing.T) {
	findings := []Finding{
		{RuleID: "secret_aws_key", Line: 2, Message: "AWS key found"},
		{RuleID: "pii_ssn", Line: 4, Message: "SSN found"},
	}
	suppressions := []Suppression{
		{RuleID: "secret_aws_key", Line: 1},
	}
	filtered := ApplySuppressions(findings, suppressions)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding after suppression, got %d", len(filtered))
	}
	if filtered[0].RuleID != "pii_ssn" {
		t.Errorf("expected pii_ssn to remain, got %s", filtered[0].RuleID)
	}
}

func TestApplySuppressions_AllKeyword(t *testing.T) {
	findings := []Finding{
		{RuleID: "secret_aws_key", Line: 2},
		{RuleID: "pii_ssn", Line: 2},
		{RuleID: "dangerous_eval", Line: 5},
	}
	suppressions := []Suppression{
		{RuleID: "all", Line: 1},
	}
	filtered := ApplySuppressions(findings, suppressions)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding after 'all' suppression, got %d", len(filtered))
	}
	if filtered[0].RuleID != "dangerous_eval" {
		t.Errorf("expected dangerous_eval to remain, got %s", filtered[0].RuleID)
	}
}

func TestApplySuppressions_NoSuppressions(t *testing.T) {
	findings := []Finding{
		{RuleID: "secret_aws_key", Line: 2},
	}
	filtered := ApplySuppressions(findings, nil)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding (no suppressions), got %d", len(filtered))
	}
}

func TestApplySuppressions_SameLineAndNextLine(t *testing.T) {
	// Suppression on line 3 should suppress findings on line 3 AND line 4.
	findings := []Finding{
		{RuleID: "secret_aws_key", Line: 3},
		{RuleID: "secret_aws_key", Line: 4},
		{RuleID: "secret_aws_key", Line: 5},
	}
	suppressions := []Suppression{
		{RuleID: "secret_aws_key", Line: 3},
	}
	filtered := ApplySuppressions(findings, suppressions)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding after suppression, got %d", len(filtered))
	}
	if filtered[0].Line != 5 {
		t.Errorf("expected finding on line 5 to remain, got line %d", filtered[0].Line)
	}
}
