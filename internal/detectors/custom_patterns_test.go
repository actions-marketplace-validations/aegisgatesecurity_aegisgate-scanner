// SPDX-License-Identifier: Apache-2.0
// Tests for custom pattern registration and NormalizeForComparison.

package detectors

import (
	"strings"
	"testing"
)

func TestRegisterCustomPatterns(t *testing.T) {
	// Save state and restore after test.
	originalCustom := customPatterns
	defer func() { customPatterns = originalCustom }()

	ResetCustomPatterns()

	defs := []PatternDef{
		{Name: "custom_test_pattern_1", Regex: `test_\d+`, Severity: SeverityHigh, Category: "custom", Description: "Test pattern 1"},
		{Name: "custom_test_pattern_2", Regex: `foobar`, Severity: SeverityMedium, Category: "custom", Description: "Test pattern 2"},
	}

	if err := RegisterCustomPatterns(defs); err != nil {
		t.Fatalf("RegisterCustomPatterns failed: %v", err)
	}

	// Verify patterns are detected.
	matches := DetectCustomPatterns("this has test_123 in it")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Category != "custom_test_pattern_1" {
		t.Errorf("expected custom_test_pattern_1, got %s", matches[0].Category)
	}
	if matches[0].Severity != SeverityHigh {
		t.Errorf("expected high severity, got %s", matches[0].Severity)
	}

	// Verify second pattern.
	matches2 := DetectCustomPatterns("foobar here")
	if len(matches2) != 1 || matches2[0].Category != "custom_test_pattern_2" {
		t.Errorf("expected custom_test_pattern_2 match, got %v", matches2)
	}
}

func TestRegisterCustomPatterns_InvalidRegex(t *testing.T) {
	ResetCustomPatterns()
	defer ResetCustomPatterns()

	defs := []PatternDef{
		{Name: "bad_pattern", Regex: `[invalid`, Severity: SeverityLow, Category: "custom"},
	}

	err := RegisterCustomPatterns(defs)
	if err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}
}

func TestRegisterCustomPatterns_InDetectAll(t *testing.T) {
	ResetCustomPatterns()
	defer ResetCustomPatterns()

	RegisterCustomPatterns([]PatternDef{
		{Name: "custom_in_detectall", Regex: `UNIQUE_MARKER_\d+`, Severity: SeverityCritical, Category: "custom"},
	})

	matches := DetectAll("text with UNIQUE_MARKER_42 here")
	found := false
	for _, m := range matches {
		if m.Category == "custom_in_detectall" {
			found = true
			if m.Severity != SeverityCritical {
				t.Errorf("expected critical, got %s", m.Severity)
			}
		}
	}
	if !found {
		t.Error("custom pattern not found in DetectAll results")
	}
}

func TestResetCustomPatterns(t *testing.T) {
	RegisterCustomPatterns([]PatternDef{
		{Name: "temp_pattern", Regex: `temp`, Severity: SeverityLow, Category: "custom"},
	})

	// Verify it works.
	if len(DetectCustomPatterns("temp")) == 0 {
		t.Fatal("pattern should match before reset")
	}

	ResetCustomPatterns()

	// Verify it no longer matches.
	if len(DetectCustomPatterns("temp")) != 0 {
		t.Error("pattern should not match after reset")
	}
}

func TestDetectCustomPatterns_NoPatterns(t *testing.T) {
	ResetCustomPatterns()
	defer ResetCustomPatterns()

	if len(DetectCustomPatterns("anything")) != 0 {
		t.Error("DetectCustomPatterns should return nil when no patterns registered")
	}
}

func TestNormalizeForComparison(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string // substring that should be in the result
	}{
		{
			name:     "plain text",
			input:    "hello world",
			contains: "hello world",
		},
		{
			name:     "uppercase normalized",
			input:    "HELLO WORLD",
			contains: "HELLO WORLD",
		},
		{
			name:     "extra whitespace collapsed",
			input:    "hello   world",
			contains: "hello world",
		},
		{
			name:     "empty string",
			input:    "",
			contains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeForComparison(tt.input)
			if tt.contains != "" && !strings.Contains(got, tt.contains) {
				t.Errorf("NormalizeForComparison(%q) = %q, should contain %q", tt.input, got, tt.contains)
			}
		})
	}
}

func TestNormalizeForComparison_AppendsVariants(t *testing.T) {
	// NormalizeForComparison appends ROT13 and keyboard walk variants.
	got := NormalizeForComparison("hello")
	// Should contain the normalized text and at least one variant.
	if !strings.Contains(got, "hello") {
		t.Errorf("result should contain normalized 'hello': %q", got)
	}
	// ROT13 of "hello" is "uryyb"
	if !strings.Contains(got, "uryyb") {
		t.Errorf("result should contain ROT13 variant 'uryyb': %q", got)
	}
}

func TestNormalizeForComparison_EvasionResistance(t *testing.T) {
	// Verify that homoglyphs are normalized in the output.
	input := "hеllo wоrld" // Contains Cyrillic homoglyphs
	got := NormalizeForComparison(input)
	// The first part should contain normalized "hello world"
	if !strings.Contains(got, "hello world") {
		t.Errorf("NormalizeForComparison with homoglyphs should contain 'hello world': %q", got)
	}
}
