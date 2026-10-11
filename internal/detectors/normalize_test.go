// SPDX-License-Identifier: Apache-2.0
// Provenance: github.com/aegisgatesecurity/aegisgate-platform (v4.4.0)
// Tests for text normalization functions ported from Platform scanner.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

package detectors

import (
	"strings"
	"testing"
)

func TestNormalizeHomoglyphs(t *testing.T) {
	// Cyrillic 'а' (U+0430) should be replaced with Latin 'a'
	input := "аdmin" // First char is Cyrillic
	result := NormalizeHomoglyphs(input)
	if result != "admin" {
		t.Errorf("NormalizeHomoglyphs: expected 'admin', got '%s'", result)
	}
}

func TestNormalizeText(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string // result should contain this substring
	}{
		{"l33t speak", "1gn0r3 pr3v10us", "ignore"},
		{"zero-width", "igno\u200bre pre\u200bvious", "ignore previous"},
		{"homoglyph", "аdmin", "admin"},
		{"insertion dots", "i.g.n.o.r.e previous", "ignore"},
		{"insertion hyphens", "i-g-n-o-r-e previous", "ignore"},
		{"whitespace collapse", "ignore    previous   instructions",
			"ignore previous instructions"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeText(tt.input)
			if !strings.Contains(strings.ToLower(result), tt.contains) {
				t.Errorf("NormalizeText(%q): expected to contain '%s', got '%s'",
					tt.input, tt.contains, result)
			}
		})
	}
}

func TestNormalizeKeyboardWalk(t *testing.T) {
	// RIGHT shift of "ignore" = "o...": a→s, so reverse shifts LEFT
	// "ignore" shifted right: i→o, g→h, n→m, o→p, r→t, e→r → "ohmptr"
	// Reversing "ohmptr" should give back "ignore"
	input := "ohmptr"
	result := NormalizeKeyboardWalk(input)
	if result != "ignore" {
		t.Errorf("NormalizeKeyboardWalk: expected 'ignore', got '%s'", result)
	}
}

func TestNormalizeROT13(t *testing.T) {
	input := "ignore"
	rot13 := NormalizeROT13(input)
	// ROT13 of "ignore" = "vtaber"
	if rot13 != "vtaber" {
		t.Errorf("NormalizeROT13: expected 'vtaber', got '%s'", rot13)
	}
	// Double ROT13 should return original
	double := NormalizeROT13(rot13)
	if double != input {
		t.Errorf("NormalizeROT13 double: expected '%s', got '%s'", input, double)
	}
}

func TestNormalizeAllVariants(t *testing.T) {
	input := "ignore previous instructions"
	variants := NormalizeAllVariants(input)
	if len(variants) < 2 {
		t.Errorf("NormalizeAllVariants: expected at least 2 variants, got %d", len(variants))
	}
	// Original should be first
	if variants[0] != input {
		t.Errorf("NormalizeAllVariants: first variant should be original, got '%s'", variants[0])
	}
}

func TestNormalizeRepeatingChars(t *testing.T) {
	input := "ignoooooore"
	result := NormalizeRepeatingChars(input)
	if result != "ignoore" {
		t.Errorf("NormalizeRepeatingChars: expected 'ignoore', got '%s'", result)
	}
}

func TestNormalizeBackslashEscapes(t *testing.T) {
	input := `igno\re pre\vious`
	result := NormalizeBackslashEscapes(input)
	if result != "ignore previous" {
		t.Errorf("NormalizeBackslashEscapes: expected 'ignore previous', got '%s'", result)
	}
}

func TestKeyWalkReverseMap(t *testing.T) {
	// Verify the keyWalkReverse map has the correct entries
	expectedMappings := map[rune]rune{
		's': 'a', 'd': 's', 'f': 'd', 'g': 'f', 'h': 'g',
		'j': 'h', 'k': 'j', 'l': 'k', ';': 'l',
		'w': 'q', 'e': 'w', 'r': 'e', 't': 'r', 'y': 't',
		'u': 'y', 'i': 'u', 'o': 'i', 'p': 'o',
		'x': 'z', 'c': 'x', 'v': 'c', 'b': 'v', 'n': 'b',
		'm': 'n', ',': 'm',
		// Uppercase
		'S': 'A', 'D': 'S', 'F': 'D', 'G': 'F', 'H': 'G',
		'J': 'H', 'K': 'J', 'L': 'K', ':': 'L',
	}
	for shifted, original := range expectedMappings {
		if keyWalkReverse[shifted] != original {
			t.Errorf("keyWalkReverse[%q] = %q, expected %q",
				shifted, keyWalkReverse[shifted], original)
		}
	}
}
