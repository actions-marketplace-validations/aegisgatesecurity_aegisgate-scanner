// SPDX-License-Identifier: Apache-2.0
// Tests for entropy-based secret detection.

package detectors

import (
	"math"
	"testing"
)

// ====================================================================
// ShannonEntropy unit tests
// ====================================================================

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  float64
	}{
		{"empty string", "", 0.0},
		{"single char repeated", "aaaa", 0.0},
		{"four unique chars", "abcd", 2.0},
		{"mixed four unique chars", "aA1!", 2.0},
		{"two chars equal split", "abab", 1.0},
		{"eight unique chars", "abcdefgh", 3.0},
	}

	const tol = 1e-9

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ShannonEntropy(tc.input)
			if math.Abs(got-tc.want) > tol {
				t.Errorf("ShannonEntropy(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestShannonEntropy_HighEntropyString(t *testing.T) {
	// A well-distributed base64-like string should have high entropy.
	s := "xK9m2vP7qR4sY8bN3cL5jF2hT6wZ1dG"
	got := ShannonEntropy(s)
	if got < 4.0 {
		t.Errorf("ShannonEntropy(%q) = %v, expected >= 4.0 for high-entropy string", s, got)
	}
}

// ====================================================================
// isHexOnly unit tests
// ====================================================================

func TestEntropyIsHexOnly(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"abcdef0123456789", true},
		{"ABCDEF0123456789", true},
		{"0123456789", true},
		{"abcdef", true},
		{"ABCDEF", true},
		{"a3f7b2c9e1d4f8a6", true},
		{"", false},
		{"g123", false},
		{"abc-def", false},
		{"xyz123", false},
		{"0x1234abcd", false},
	}

	for _, tc := range tests {
		got := isHexOnly(tc.input)
		if got != tc.want {
			t.Errorf("isHexOnly(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

// ====================================================================
// DetectEntropy integration tests
// ====================================================================

func TestEntropyDetect_HighEntropyBase64(t *testing.T) {
	text := `api_key = "xK9m2vP7qR4sY8bN3cL5jF2hT6wZ1dG"`
	matches := DetectEntropy(text)
	if len(matches) == 0 {
		t.Fatal("expected at least 1 match for high-entropy base64 near keyword, got 0")
	}
	m := matches[0]
	if m.Category != "entropy_high_string" {
		t.Errorf("Category = %q, want %q", m.Category, "entropy_high_string")
	}
	if m.Severity != SeverityMedium {
		t.Errorf("Severity = %q, want %q", m.Severity, SeverityMedium)
	}
	if m.Confidence < 0.5 || m.Confidence > 0.9 {
		t.Errorf("Confidence = %v, want in range [0.5, 0.9]", m.Confidence)
	}
	if m.Value == "" {
		t.Error("Value should not be empty")
	}
}

func TestEntropyDetect_HighEntropyHex(t *testing.T) {
	// 32-char hex string with good distribution near "secret" keyword.
	text := `secret = "a3f7b2c9e1d4f8a6b5c3e7d9f2a1b4c8"`
	matches := DetectEntropy(text)
	if len(matches) == 0 {
		t.Fatal("expected at least 1 match for high-entropy hex near keyword, got 0")
	}
	m := matches[0]
	if m.Category != "entropy_high_string" {
		t.Errorf("Category = %q, want %q", m.Category, "entropy_high_string")
	}
	if m.Confidence < 0.5 {
		t.Errorf("Confidence = %v, want >= 0.5", m.Confidence)
	}
}

func TestEntropyDetect_LowEntropy(t *testing.T) {
	text := `This is just normal English text without any secrets or keys in it.
The quick brown fox jumps over the lazy dog. Nothing to see here.`
	matches := DetectEntropy(text)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for low-entropy text, got %d", len(matches))
		for _, m := range matches {
			t.Logf("unexpected match: Value=%q Confidence=%v Index=%d", m.Value, m.Confidence, m.Index)
		}
	}
}

func TestEntropyDetect_NoKeyword(t *testing.T) {
	// Standalone high-entropy string with no keyword nearby.
	text := `xK9m2vP7qR4sY8bN3cL5jF2hT6wZ1dG`
	matches := DetectEntropy(text)
	if len(matches) == 0 {
		t.Fatal("expected at least 1 match for standalone high-entropy string, got 0")
	}
	if matches[0].Value != "xK9m2vP7qR4sY8bN3cL5jF2hT6wZ1dG" {
		t.Errorf("Value = %q, want %q", matches[0].Value, "xK9m2vP7qR4sY8bN3cL5jF2hT6wZ1dG")
	}
}

func TestEntropyDetect_EmptyString(t *testing.T) {
	matches := DetectEntropy("")
	if matches != nil {
		t.Errorf("DetectEntropy(\"\") = %v, want nil", matches)
	}
}

func TestEntropyDetect_Deduplication(t *testing.T) {
	// The value "xK9m2vP7qR4sY8bN3cL5jF2hT6wZ1dG" will be found by both
	// the keyword-adjacent pass and the standalone pass. After dedup,
	// only 1 match should remain.
	text := `api_key = "xK9m2vP7qR4sY8bN3cL5jF2hT6wZ1dG"`
	matches := DetectEntropy(text)
	if len(matches) != 1 {
		t.Errorf("expected 1 match after deduplication, got %d", len(matches))
		for _, m := range matches {
			t.Logf("match: Value=%q Index=%d End=%d Confidence=%v", m.Value, m.Index, m.End, m.Confidence)
		}
	}
}

func TestEntropyDetect_RealWorldSecrets(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		{
			name: "custom api key assignment",
			text: `api_key = "xK9m2vP7qR4sY8bN3cL5jF2hT6wZ1dG"`,
		},
		{
			name: "secret token with colon",
			text: `secret_token: "ZmYxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnh5eg"`,
		},
		{
			name: "access key equals",
			text: `ACCESS_KEY = Bp3nK7mQ2vR9sY4cL8jF5hT1wZ6dG0xN`,
		},
		{
			name: "bearer token",
			text: `Authorization: Bearer xK9m2vP7qR4sY8bN3cL5jF2hT6wZ1dG`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matches := DetectEntropy(tc.text)
			if len(matches) == 0 {
				t.Errorf("expected at least 1 match for %q, got 0", tc.text)
			}
		})
	}
}

func TestEntropyDetect_FalsePositiveResistance(t *testing.T) {
	// Text containing URLs, UUIDs, file paths, and normal code that
	// should NOT be flagged as secrets.
	text := `package main

import "fmt"

const defaultURL = "https://example.com/path/to/resource"
const uuid = "550e8400-e29b-41d4-a716-446655440000"

func main() {
    fmt.Println("hello world")
    var x = []int{1, 2, 3, 4, 5}
    path := "/usr/local/bin/python3"
    _ = path
    _ = x
}
`
	matches := DetectEntropy(text)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for false-positive text, got %d", len(matches))
		for _, m := range matches {
			t.Logf("unexpected match: Value=%q Confidence=%v Index=%d", m.Value, m.Confidence, m.Index)
		}
	}
}

// ====================================================================
// Additional edge case tests
// ====================================================================

func TestEntropyDetect_MultipleSecrets(t *testing.T) {
	text := `api_key = "xK9m2vP7qR4sY8bN3cL5jF2hT6wZ1dG"
secret = "Bp3nK7mQ2vR9sY4cL8jF5hT1wZ6dG0xN"`
	matches := DetectEntropy(text)
	if len(matches) < 2 {
		t.Errorf("expected at least 2 matches for multiple secrets, got %d", len(matches))
	}
}

func TestEntropyDetect_ShortStringNearKeyword(t *testing.T) {
	// A short string near a keyword should not be flagged (below MinSecretLength).
	text := `api_key = "short123"`
	matches := DetectEntropy(text)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for short string, got %d", len(matches))
	}
}

func TestEntropyDetect_HexStandaloneNotFlagged(t *testing.T) {
	// A standalone hex string without mixed case should not be flagged
	// by the standalone pass (requires mixed case + digits).
	text := `a3f7b2c9e1d4f8a6b5c3e7d9f2a1b4c8`
	matches := DetectEntropy(text)
	// Hex-only strings are all lowercase (or all uppercase) + digits,
	// so hasMixedCaseAndDigits returns false and they are filtered out
	// in the standalone pass. This is intentional to reduce false positives.
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for standalone lowercase hex, got %d", len(matches))
		for _, m := range matches {
			t.Logf("unexpected match: Value=%q", m.Value)
		}
	}
}

func TestEntropyDetect_Constants(t *testing.T) {
	if EntropyThresholdBase64 != 4.5 {
		t.Errorf("EntropyThresholdBase64 = %v, want 4.5", EntropyThresholdBase64)
	}
	if EntropyThresholdHex != 3.0 {
		t.Errorf("EntropyThresholdHex = %v, want 3.0", EntropyThresholdHex)
	}
	if MinSecretLength != 20 {
		t.Errorf("MinSecretLength = %v, want 20", MinSecretLength)
	}
	if MaxSecretLength != 200 {
		t.Errorf("MaxSecretLength = %v, want 200", MaxSecretLength)
	}
}
