// SPDX-License-Identifier: Apache-2.0
// Provenance: github.com/aegisgatesecurity/aegisgate-platform/upstream/aegisgate/pkg/scanner/normalize.go (v4.4.0)
// =========================================================================
// AegisGate Rampart - Text Normalization for Evasion Resistance
// =========================================================================
//
// Provides normalization functions that deobfuscate common evasion techniques
// (l33t speak, keyboard shifts, character insertion, zero-width chars) so that
// downstream pattern matching can detect evaded attack payloads.
//
// Ported from AegisGate Platform scanner normalize.go to bring evasion
// resistance parity to Rampart's detector engine.
//
// Design principle: NormalizeText() applies ONLY idempotent transformations.
// Keyboard-walk reversal and ROT13 decoding are DESTRUCTIVE on normal text,
// so they are provided as separate functions. The caller should scan the
// original text PLUS all normalized variants.
//
// =========================================================================

package detectors

import (
	"strings"
	"unicode"
)

// homoglyphMap maps common visually-confusable Unicode characters (Cyrillic,
// Greek, and other lookalikes) to their Latin ASCII equivalents.
var homoglyphMap = map[rune]rune{
	// Cyrillic → Latin lookalikes
	'а': 'a', 'А': 'a', 'е': 'e', 'Е': 'e', 'о': 'o', 'О': 'o',
	'р': 'p', 'Р': 'p', 'с': 'c', 'С': 'c', 'х': 'x', 'Х': 'x',
	'у': 'y', 'У': 'y', 'і': 'i', 'І': 'i', 'ј': 'j', 'Ј': 'j',
	'ѕ': 's', 'Ѕ': 's', 'қ': 'q',
	// Greek → Latin lookalikes
	'α': 'a', 'Α': 'a', 'ε': 'e', 'Ε': 'e', 'ο': 'o', 'Ο': 'o',
	'ν': 'v', 'Ν': 'v', 'ρ': 'p', 'Ρ': 'p', 'τ': 't', 'Τ': 't',
}

// l33tMap maps l33t-speak substitutions back to their letter equivalents.
var l33tMap = map[rune]rune{
	'@': 'a', '4': 'a', '8': 'b', '(': 'c', '3': 'e', '6': 'g',
	'9': 'g', '1': 'i', '|': 'i', '!': 'i', '0': 'o', '5': 's',
	'$': 's', '7': 't', '2': 'z',
}

// keyWalkReverse maps QWERTY right-shifted keys back to their original position.
// This is the exact inverse of the keyboardWalkShift transform used in both the
// augmentation engine (augment.go) and the evasion suite test (evasion_suite_test.go).
// Both use RIGHT shift (a→s, s→d, etc.), so we reverse with LEFT shift (s→a, d→s, etc.).
// Includes mappings for ; and , (the shifted outputs of l and m), plus uppercase.
var keyWalkReverse = map[rune]rune{
	// Home row (lowercase): s→a, d→s, f→d, g→f, h→g, j→h, k→j, l→k, ;→l
	's': 'a', 'd': 's', 'f': 'd', 'g': 'f', 'h': 'g', 'j': 'h', 'k': 'j', 'l': 'k', ';': 'l',
	// Top row (lowercase): w→q, e→w, r→e, t→r, y→t, u→y, i→u, o→i, p→o
	'w': 'q', 'e': 'w', 'r': 'e', 't': 'r', 'y': 't', 'u': 'y', 'i': 'u', 'o': 'i', 'p': 'o',
	// Bottom row (lowercase): x→z, c→x, v→c, b→v, n→b, m→n, ,→m
	'x': 'z', 'c': 'x', 'v': 'c', 'b': 'v', 'n': 'b', 'm': 'n', ',': 'm',
	// Uppercase (same shifts, uppercase output)
	'S': 'A', 'D': 'S', 'F': 'D', 'G': 'F', 'H': 'G', 'J': 'H', 'K': 'J', 'L': 'K', ':': 'L',
	'W': 'Q', 'E': 'W', 'R': 'E', 'T': 'R', 'Y': 'T', 'U': 'Y', 'I': 'U', 'O': 'I', 'P': 'O',
	'X': 'Z', 'C': 'X', 'V': 'C', 'B': 'V', 'N': 'B', 'M': 'N', '<': 'M',
}

// zeroWidthSet is a lookup set for zero-width/invisible Unicode characters.
var zeroWidthSet = func() map[rune]bool {
	runes := []rune{
		'\u200b', '\u200c', '\u200d', '\u200f', // ZW space, ZWNJ, ZWJ, RTL mark
		'\u2028', '\u2029', // Line/paragraph separator
		'\u202a', '\u202b', '\u202c', '\u202d', '\u202e', // Directional overrides
		'\u00ad', '\ufeff', // Soft hyphen, BOM/ZWNBS
		'\u2000', '\u2001', '\u2002', '\u2003', // En/Em quad, En/Em space
		'\u2004', '\u2005', '\u2006', // Three/Four/Six-Per-Em
		'\u2007', '\u2008', '\u2009', '\u200a', // Figure/Punct/Thin/Hair space
		'\u00a0', // NBSP
	}
	m := make(map[rune]bool, len(runes))
	for _, r := range runes {
		m[r] = true
	}
	return m
}()

// NormalizeHomoglyphs replaces visually-confusable Unicode characters with
// their ASCII equivalents.
func NormalizeHomoglyphs(input string) string {
	runes := []rune(input)
	result := make([]rune, len(runes))
	for i, r := range runes {
		if replacement, ok := homoglyphMap[r]; ok {
			result[i] = replacement
		} else {
			result[i] = r
		}
	}
	return string(result)
}

// deobfuscateL33t reverses common l33t-speak substitutions.
func deobfuscateL33t(s string) string {
	runes := []rune(s)
	result := make([]rune, len(runes))
	for i, r := range runes {
		if replacement, ok := l33tMap[r]; ok {
			result[i] = replacement
		} else {
			result[i] = r
		}
	}
	return string(result)
}

// stripZeroWidth removes zero-width and invisible Unicode characters.
func stripZeroWidth(s string) string {
	runes := []rune(s)
	result := make([]rune, 0, len(runes))
	for _, r := range runes {
		if !zeroWidthSet[r] {
			result = append(result, r)
		}
	}
	return string(result)
}

// collapseWhitespace collapses multiple whitespace characters into single spaces.
func collapseWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// removeInterCharacterInsertions strips dots, hyphens, and underscores that
// appear between alphanumeric characters within words.
func removeInterCharacterInsertions(s string) string {
	runes := []rune(s)
	if len(runes) < 3 {
		return s
	}
	result := make([]rune, 0, len(runes))
	insertionChars := map[rune]bool{'.': true, '-': true, '_': true}

	for i, r := range runes {
		if insertionChars[r] {
			hasLetterBefore := i > 0 && unicode.IsLetter(runes[i-1])
			hasLetterAfter := i < len(runes)-1 && unicode.IsLetter(runes[i+1])
			if hasLetterBefore || hasLetterAfter {
				continue // Skip insertion character
			}
		}
		result = append(result, r)
	}
	return string(result)
}

// reverseKeyboardWalk shifts each key one position LEFT on QWERTY.
func reverseKeyboardWalk(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if replacement, ok := keyWalkReverse[r]; ok {
			b.WriteRune(replacement)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// NormalizeText applies all IDEMPOTENT normalizations to the input text.
// These transformations are safe to apply to any text — they won't corrupt
// legitimate content. Destructive transforms (keyboard walk reversal, ROT13)
// are NOT applied here; use NormalizeAllVariants() for those.
func NormalizeText(input string) string {
	// 1. Strip zero-width characters
	result := stripZeroWidth(input)
	// 2. Normalize homoglyphs
	result = NormalizeHomoglyphs(result)
	// 3. Deobfuscate l33t speak
	result = deobfuscateL33t(result)
	// 4. Remove inter-character insertions (dots, hyphens between letters)
	result = removeInterCharacterInsertions(result)
	// 5. Collapse whitespace
	result = collapseWhitespace(result)
	return result
}

// NormalizeKeyboardWalk applies keyboard-walk reversal (destructive).
func NormalizeKeyboardWalk(input string) string {
	return reverseKeyboardWalk(strings.ToLower(input))
}

// NormalizeROT13 applies ROT13 decoding (destructive).
func NormalizeROT13(input string) string {
	runes := []rune(input)
	result := make([]rune, len(runes))
	for i, r := range runes {
		if r >= 'a' && r <= 'z' {
			result[i] = ((r - 'a' + 13) % 26) + 'a'
		} else if r >= 'A' && r <= 'Z' {
			result[i] = ((r - 'A' + 13) % 26) + 'A'
		} else {
			result[i] = r
		}
	}
	return string(result)
}

// NormalizeForComparison applies NormalizeText + keyboard walk + ROT13.
// Returns the most aggressive normalization for comparison purposes.
func NormalizeForComparison(input string) string {
	result := NormalizeText(input)
	// Also try keyboard walk reversal
	kw := NormalizeKeyboardWalk(input)
	if len(kw) > 0 {
		result = result + " " + kw
	}
	// Also try ROT13
	rot := NormalizeROT13(input)
	if len(rot) > 0 {
		result = result + " " + rot
	}
	return result
}

// NormalizeAllVariants returns the original text plus all normalized variants.
// The caller should scan each variant against detection patterns.
// NormalizeSlidingROT13 applies ROT13 decoding to sliding windows of 4+
// consecutive alphabetic characters within the input. This catches attacks
// where only part of the text is ROT13-encoded (e.g., "vtaber previous"
// where "vtaber" decodes to "ignore"). Returns up to 5 unique variants,
// each with a different window decoded. If no suitable alphabetic runs are
// found, returns an empty slice.
//
// Ported from Platform scanner/normalize.go (v4.4.0).
func NormalizeSlidingROT13(input string) []string {
	type run struct {
		start int
		end   int
	}
	runes := []rune(input)

	var runs []run
	i := 0
	for i < len(runes) {
		if unicode.IsLetter(runes[i]) {
			start := i
			for i < len(runes) && unicode.IsLetter(runes[i]) {
				i++
			}
			if i-start >= 4 {
				runs = append(runs, run{start: start, end: i})
			}
		} else {
			i++
		}
	}

	if len(runs) == 0 {
		return nil
	}

	var variants []string
	seen := map[string]bool{}

	for _, r := range runs {
		var b strings.Builder
		b.Grow(len(input))
		for j, ch := range runes {
			if j >= r.start && j < r.end {
				switch {
				case ch >= 'a' && ch <= 'z':
					b.WriteRune((ch-'a'+13)%26 + 'a')
				case ch >= 'A' && ch <= 'Z':
					b.WriteRune((ch-'A'+13)%26 + 'A')
				default:
					b.WriteRune(ch)
				}
			} else {
				b.WriteRune(ch)
			}
		}
		v := b.String()
		if v != input && !seen[v] {
			seen[v] = true
			variants = append(variants, v)
			if len(variants) >= 5 {
				break
			}
		}
	}

	return variants
}

func NormalizeAllVariants(input string) []string {
	variants := []string{
		input,
		NormalizeText(input),
		NormalizeKeyboardWalk(input),
		NormalizeROT13(input),
		NormalizeText(NormalizeKeyboardWalk(input)),
		NormalizeText(NormalizeROT13(input)),
	}

	// Additional variants for parity with Platform
	repeating := NormalizeRepeatingChars(input)
	if repeating != input && repeating != "" {
		variants = append(variants, repeating)
	}
	backslash := NormalizeBackslashEscapes(input)
	if backslash != input && backslash != "" {
		variants = append(variants, backslash)
	}
	homoglyphs := NormalizeHomoglyphs(input)
	if homoglyphs != input && homoglyphs != "" {
		variants = append(variants, homoglyphs)
		homoglyphNorm := NormalizeText(homoglyphs)
		if homoglyphNorm != homoglyphs && homoglyphNorm != input && homoglyphNorm != "" {
			variants = append(variants, homoglyphNorm)
		}
	}

	// Sliding ROT13 variants (parity with Platform)
	variants = append(variants, NormalizeSlidingROT13(input)...)

	// Deduplicate
	seen := make(map[string]bool, len(variants))
	unique := make([]string, 0, len(variants))
	for _, v := range variants {
		if v != "" && !seen[v] {
			seen[v] = true
			unique = append(unique, v)
		}
	}
	return unique
}

// NormalizeRepeatingChars collapses 3+ consecutive identical characters to 2.
func NormalizeRepeatingChars(input string) string {
	runes := []rune(input)
	if len(runes) < 3 {
		return input
	}
	result := make([]rune, 0, len(runes))
	count := 1
	for i := 0; i < len(runes); i++ {
		if i > 0 && runes[i] == runes[i-1] {
			count++
		} else {
			count = 1
		}
		if count <= 2 {
			result = append(result, runes[i])
		}
	}
	return string(result)
}

// NormalizeBackslashEscapes removes backslash escape sequences (e.g., \x41 → A).
func NormalizeBackslashEscapes(input string) string {
	return strings.ReplaceAll(input, "\\", "")
}
