// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Known Example Value Suppression — Tests
// =========================================================================

package detectors

import (
	"testing"
)

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// allKnownExampleValues returns every key from KnownExampleValues as a slice,
// making sure tests automatically cover future additions.
func allKnownExampleValues() []string {
	out := make([]string, 0, len(KnownExampleValues))
	for v := range KnownExampleValues {
		out = append(out, v)
	}
	return out
}

// --------------------------------------------------------------------------
// IsKnownExample
// --------------------------------------------------------------------------

func TestIsKnownExample_ExactMatch(t *testing.T) {
	for _, val := range allKnownExampleValues() {
		if !IsKnownExample(val) {
			t.Errorf("expected exact match for known example value %q", val)
		}
	}
}

func TestIsKnownExample_PrefixMatch(t *testing.T) {
	cases := []struct {
		value  string
		prefix string
	}{
		// Each prefix should match a value that starts with it.
		{"AKIAIOSFODNN7EXAMPLE_extra", "AKIAIOSFODNN7"},
		{"wJalrXUtnFEMI/morestuff", "wJalrXUtnFEMI"},
		{"ghp_0123456789abcdextra", "ghp_0123456789"},
		{"gho_0123456789abcdextra", "gho_0123456789"},
		{"ghs_0123456789abcdextra", "ghs_0123456789"},
		{"ghu_0123456789abcdextra", "ghu_0123456789"},
		{"sk_test_1234567890abcdefghijklmnopqrstuvwxyz", "sk_test_"},
		{"pk_test_1234567890abcdefghijklmnopqrstuvwxyz", "pk_test_"},
		{"xoxb-0000000000-0000000000-000000000000000000000000extra", "xoxb-0000000000"},
		{"xoxp-0000000000-someextra", "xoxp-0000000000"},
		{"AIzaSyD_fake_extra_stuff", "AIzaSyD_fake"},
		{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkw.extra.sig", "JWT example header+payload"},
	}
	for _, c := range cases {
		if !IsKnownExample(c.value) {
			t.Errorf("expected prefix %q to match value %q", c.prefix, c.value)
		}
	}
}

func TestIsKnownExample_RealSecret(t *testing.T) {
	// A real-looking secret that is NOT a known example and contains no
	// test/example keywords.
	real := "AKIAZ7k2mP4qR7sT1vW3xY5aB8"
	if IsKnownExample(real) {
		t.Errorf("did not expect real-looking secret %q to match as known example", real)
	}
}

func TestIsKnownExample_PrivateKeyPrefix(t *testing.T) {
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
	if !IsKnownExample(pem) {
		t.Errorf("expected PEM private key example block to be recognised as known example")
	}
}

func TestIsKnownExample_Empty(t *testing.T) {
	if IsKnownExample("") {
		t.Errorf("empty string should not be a known example")
	}
}

// --------------------------------------------------------------------------
// IsExampleByContent
// --------------------------------------------------------------------------

func TestIsExampleByContent_TestKeywords(t *testing.T) {
	cases := []string{
		"my_example_secret_value",
		"this_is_a_test_key",
		"dummy_value_123",
		"placeholder_for_production",
		"fake_api_key_here",
		"sample_data_abc",
		"demo_credentials_xyz",
	}
	for _, v := range cases {
		if !IsExampleByContent(v) {
			t.Errorf("expected value %q to be detected as example by content", v)
		}
	}
}

func TestIsExampleByContent_RepeatedDigits(t *testing.T) {
	v := "abc01234567890123456789xyz"
	if !IsExampleByContent(v) {
		t.Errorf("expected value with repeated 0123456789 to be detected as example by content")
	}
}

func TestIsExampleByContent_AllSameChar(t *testing.T) {
	cases := []string{
		"aaaaaaaaaa",
		"0000000000000000000000000000000000000000",
		"xxxxxxxxxx",
	}
	for _, v := range cases {
		if !IsExampleByContent(v) {
			t.Errorf("expected all-same-char value %q to be detected as example by content", v)
		}
	}
}

func TestIsExampleByContent_Sequential(t *testing.T) {
	cases := []string{
		"abcdef123456",
		"token_fedcba",
		"secret_987654",
	}
	for _, v := range cases {
		if !IsExampleByContent(v) {
			t.Errorf("expected sequential value %q to be detected as example by content", v)
		}
	}
}

func TestIsExampleByContent_RealValue(t *testing.T) {
	real := "Z9k2mP4qR7sT1vW3xY5aB8cD0eF2gH4"
	if IsExampleByContent(real) {
		t.Errorf("did not expect real-looking value %q to be detected as example by content", real)
	}
}

// --------------------------------------------------------------------------
// FilterKnownExamples
// --------------------------------------------------------------------------

func TestFilterKnownExamples_Mixed(t *testing.T) {
	matches := []Match{
		{Category: "aws", Severity: SeverityCritical, Confidence: 0.95, Value: "AKIAIOSFODNN7EXAMPLE"},
		{Category: "aws", Severity: SeverityCritical, Confidence: 0.9, Value: "AKIAZ7k2mP4qR7sT1vW3xY5aB8"},
		{Category: "github", Severity: SeverityHigh, Confidence: 0.9, Value: "ghp_0123456789012345678901234567890123456789"},
		{Category: "generic", Severity: SeverityMedium, Confidence: 0.8, Value: "Z9k2mP4qR7sT1vW3xY5aB8cD0eF2gH4"},
	}

	kept, suppressed := FilterKnownExamples(matches)

	if len(kept) != 2 {
		t.Errorf("expected 2 kept matches, got %d", len(kept))
	}
	if len(suppressed) != 2 {
		t.Errorf("expected 2 suppressed matches, got %d", len(suppressed))
	}

	for _, s := range suppressed {
		if s.Confidence != 0.1 {
			t.Errorf("expected suppressed match confidence 0.1, got %f for value %q", s.Confidence, s.Value)
		}
	}

	for _, k := range kept {
		if k.Confidence == 0.1 {
			t.Errorf("kept match should not have reduced confidence, got 0.1 for value %q", k.Value)
		}
	}
}

func TestFilterKnownExamples_AllExamples(t *testing.T) {
	matches := []Match{
		{Category: "aws", Severity: SeverityCritical, Confidence: 0.95, Value: "AKIAIOSFODNN7EXAMPLE"},
		{Category: "github", Severity: SeverityHigh, Confidence: 0.9, Value: "ghp_0123456789012345678901234567890123456789"},
		{Category: "stripe", Severity: SeverityHigh, Confidence: 0.9, Value: "sk_test_1234567890abcdefghijklmnopqrstuvwxyz"},
	}

	kept, suppressed := FilterKnownExamples(matches)

	if len(kept) != 0 {
		t.Errorf("expected 0 kept matches, got %d", len(kept))
	}
	if len(suppressed) != 3 {
		t.Errorf("expected 3 suppressed matches, got %d", len(suppressed))
	}
}

func TestFilterKnownExamples_AllReal(t *testing.T) {
	matches := []Match{
		{Category: "aws", Severity: SeverityCritical, Confidence: 0.95, Value: "AKIAZ7k2mP4qR7sT1vW3xY5aB8"},
		{Category: "generic", Severity: SeverityMedium, Confidence: 0.8, Value: "Z9k2mP4qR7sT1vW3xY5aB8cD0eF2gH4"},
	}

	kept, suppressed := FilterKnownExamples(matches)

	if len(kept) != 2 {
		t.Errorf("expected 2 kept matches, got %d", len(kept))
	}
	if len(suppressed) != 0 {
		t.Errorf("expected 0 suppressed matches, got %d", len(suppressed))
	}
}

func TestFilterKnownExamples_Empty(t *testing.T) {
	kept, suppressed := FilterKnownExamples(nil)
	if len(kept) != 0 || len(suppressed) != 0 {
		t.Errorf("expected empty results for nil input, got kept=%d suppressed=%d", len(kept), len(suppressed))
	}
}

// --------------------------------------------------------------------------
// SuppressExamples
// --------------------------------------------------------------------------

func TestSuppressExamples(t *testing.T) {
	matches := []Match{
		{Category: "aws", Severity: SeverityCritical, Confidence: 0.95, Value: "AKIAIOSFODNN7EXAMPLE"},
		{Category: "aws", Severity: SeverityCritical, Confidence: 0.9, Value: "AKIAZ7k2mP4qR7sT1vW3xY5aB8"},
		{Category: "github", Severity: SeverityHigh, Confidence: 0.9, Value: "ghp_0123456789012345678901234567890123456789"},
		{Category: "generic", Severity: SeverityMedium, Confidence: 0.8, Value: "Z9k2mP4qR7sT1vW3xY5aB8cD0eF2gH4"},
		{Category: "stripe", Severity: SeverityHigh, Confidence: 0.9, Value: "sk_test_1234567890abcdefghijklmnopqrstuvwxyz"},
	}

	result := SuppressExamples(matches)
	if len(result) != 2 {
		t.Errorf("expected 2 non-example matches after suppression, got %d", len(result))
	}
}

func TestSuppressExamples_AllReal(t *testing.T) {
	matches := []Match{
		{Category: "aws", Severity: SeverityCritical, Confidence: 0.95, Value: "AKIAZ7k2mP4qR7sT1vW3xY5aB8"},
		{Category: "generic", Severity: SeverityMedium, Confidence: 0.8, Value: "Z9k2mP4qR7sT1vW3xY5aB8cD0eF2gH4"},
	}

	result := SuppressExamples(matches)
	if len(result) != 2 {
		t.Errorf("expected all 2 real matches to remain, got %d", len(result))
	}
}

func TestSuppressExamples_AllExamples(t *testing.T) {
	matches := []Match{
		{Category: "aws", Severity: SeverityCritical, Confidence: 0.95, Value: "AKIAIOSFODNN7EXAMPLE"},
		{Category: "github", Severity: SeverityHigh, Confidence: 0.9, Value: "ghp_0123456789012345678901234567890123456789"},
		{Category: "stripe", Severity: SeverityHigh, Confidence: 0.9, Value: "sk_test_1234567890abcdefghijklmnopqrstuvwxyz"},
		{Category: "slack", Severity: SeverityMedium, Confidence: 0.85, Value: "xoxb-0000000000-0000000000-000000000000000000000000"},
	}

	result := SuppressExamples(matches)
	if len(result) != 0 {
		t.Errorf("expected 0 matches after suppressing all examples, got %d", len(result))
	}
}

func TestSuppressExamples_Empty(t *testing.T) {
	result := SuppressExamples(nil)
	if len(result) != 0 {
		t.Errorf("expected empty result for nil input, got %d", len(result))
	}
}
