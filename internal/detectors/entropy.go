// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Entropy-Based Secret Detection
// =========================================================================
//
// Detects high-entropy strings that are likely secrets, API keys, or tokens
// even when they don't match any known format. Uses Shannon entropy to
// measure the randomness of candidate strings found near secret-related
// keywords or as standalone high-entropy values.
//
// This catches the "unknown unknowns" — custom API keys, internal tokens,
// and proprietary credentials that regex patterns can't anticipate.
//
// =========================================================================

package detectors

import (
	"math"
	"regexp"
	"sort"
)

// Entropy detection thresholds and limits.
const (
	// EntropyThresholdBase64 is the minimum Shannon entropy (bits/char)
	// for a string to be flagged as a potential secret when it contains
	// characters beyond hex (i.e., base64-like alphabets).
	EntropyThresholdBase64 = 4.5

	// EntropyThresholdHex is the minimum Shannon entropy for strings
	// that contain only hexadecimal characters [0-9a-fA-F]. Hex strings
	// have a lower maximum entropy (log2(16) = 4.0) so a lower threshold
	// is appropriate.
	EntropyThresholdHex = 3.0

	// MinSecretLength is the minimum candidate string length to consider.
	// Strings shorter than this are unlikely to be secrets and would
	// produce unreliable entropy measurements.
	MinSecretLength = 20

	// MaxSecretLength is the maximum candidate string length. Strings
	// longer than this are likely data blobs rather than individual
	// secrets and are excluded to avoid false positives.
	MaxSecretLength = 200
)

// keywordValueRe matches secret-related keywords followed by a separator
// and a high-entropy value. The capturing group extracts the value itself.
// Keywords are ordered longest-first to prevent partial alternation matches
// (e.g., "api_key" before "key").
var keywordValueRe = regexp.MustCompile(
	`(?i)\b(?:private[_-]?key|access[_-]?key|api[_-]?key|apikey|password|passwd|secret|token|credential|bearer|auth|key)\s*[:=]\s*['"]?([A-Za-z0-9_\-+/=]{20,})`,
)

// bearerTokenRe matches the "Bearer <token>" format used in HTTP
// Authorization headers. This is a common real-world secret format
// that doesn't use the keyword[:=]value pattern.
var bearerTokenRe = regexp.MustCompile(
	`(?i)\bBearer\s+([A-Za-z0-9_\-+/=\.]{20,})`,
)

// standaloneCandidateRe matches contiguous sequences of secret-like
// characters (alphanumeric, underscore, hyphen, plus, slash, equals)
// of length 20 or greater. These are filtered further by mixed-case
// and digit requirements in DetectEntropy.
var standaloneCandidateRe = regexp.MustCompile(
	`[A-Za-z0-9_\-+/=]{20,}`,
)

// ShannonEntropy calculates the Shannon entropy of a string in bits per
// character. The formula is: H = -sum(p_i * log2(p_i)) where p_i is the
// relative frequency of character i in the string.
//
// Returns 0 for empty strings or strings with a single unique character.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	freq := make(map[rune]int)
	count := 0
	for _, c := range s {
		freq[c]++
		count++
	}

	length := float64(count)
	var entropy float64
	for _, f := range freq {
		p := float64(f) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// isHexOnly returns true if the string contains only hexadecimal characters
// [0-9a-fA-F]. Returns false for empty strings.
func isHexOnly(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') ||
			(c >= 'a' && c <= 'f') ||
			(c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// hasMixedCaseAndDigits returns true if the string contains at least one
// uppercase letter, one lowercase letter, and one digit. This heuristic
// filters out normal English words, file paths, and other non-secret
// strings that may have high length but low randomness.
func hasMixedCaseAndDigits(s string) bool {
	var hasUpper, hasLower, hasDigit bool
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		}
	}
	return hasUpper && hasLower && hasDigit
}

// entropyToConfidence maps an entropy value to a confidence score in the
// range [0.5, 0.9]. Higher entropy relative to the threshold yields higher
// confidence. The mapping is linear over a 1.5-bit range above the
// threshold, clamped to the [0.5, 0.9] range.
func entropyToConfidence(entropy, threshold float64) float64 {
	conf := 0.5 + (entropy-threshold)/1.5*0.4
	if conf < 0.5 {
		conf = 0.5
	}
	if conf > 0.9 {
		conf = 0.9
	}
	return conf
}

// DetectEntropy scans text for high-entropy strings that are likely secrets,
// API keys, or tokens. It uses two complementary strategies:
//
//  1. Keyword-adjacent detection: finds values assigned near secret-related
//     keywords (key, token, secret, password, etc.) and checks their entropy.
//
//  2. Standalone detection: finds high-entropy strings of length 20+ that
//     contain mixed case and digits, even without a nearby keyword.
//
// Candidates must exceed the appropriate entropy threshold (4.5 for
// base64-like strings, 3.0 for hex-only strings). Overlapping matches are
// deduplicated, keeping the match with the highest confidence.
func DetectEntropy(text string) []Match {
	if len(text) == 0 {
		return nil
	}

	var candidates []Match

	// ---- Pass 1: keyword-adjacent values ----
	for _, idx := range keywordValueRe.FindAllStringSubmatchIndex(text, -1) {
		if len(idx) < 4 {
			continue
		}
		start, end := idx[2], idx[3]
		value := text[start:end]
		if len(value) < MinSecretLength || len(value) > MaxSecretLength {
			continue
		}
		entropy := ShannonEntropy(value)
		threshold := EntropyThresholdBase64
		if isHexOnly(value) {
			threshold = EntropyThresholdHex
		}
		if entropy >= threshold {
			candidates = append(candidates, Match{
				Category:   "entropy_high_string",
				Severity:   SeverityMedium,
				Confidence: entropyToConfidence(entropy, threshold),
				Value:      value,
				Index:      start,
				End:        end,
			})
		}
	}

	// ---- Pass 1b: Bearer token format ----
	for _, idx := range bearerTokenRe.FindAllStringSubmatchIndex(text, -1) {
		if len(idx) < 4 {
			continue
		}
		start, end := idx[2], idx[3]
		value := text[start:end]
		if len(value) < MinSecretLength || len(value) > MaxSecretLength {
			continue
		}
		entropy := ShannonEntropy(value)
		threshold := EntropyThresholdBase64
		if isHexOnly(value) {
			threshold = EntropyThresholdHex
		}
		if entropy >= threshold {
			candidates = append(candidates, Match{
				Category:   "entropy_high_string",
				Severity:   SeverityMedium,
				Confidence: entropyToConfidence(entropy, threshold),
				Value:      value,
				Index:      start,
				End:        end,
			})
		}
	}

	// ---- Pass 2: standalone high-entropy strings ----
	for _, idx := range standaloneCandidateRe.FindAllStringIndex(text, -1) {
		start, end := idx[0], idx[1]
		value := text[start:end]
		if len(value) < MinSecretLength || len(value) > MaxSecretLength {
			continue
		}
		if !hasMixedCaseAndDigits(value) {
			continue
		}
		entropy := ShannonEntropy(value)
		threshold := EntropyThresholdBase64
		if isHexOnly(value) {
			threshold = EntropyThresholdHex
		}
		if entropy >= threshold {
			candidates = append(candidates, Match{
				Category:   "entropy_high_string",
				Severity:   SeverityMedium,
				Confidence: entropyToConfidence(entropy, threshold),
				Value:      value,
				Index:      start,
				End:        end,
			})
		}
	}

	return dedupEntropyMatches(candidates)
}

// dedupEntropyMatches removes overlapping matches, keeping the one with
// the highest confidence score. Matches are first sorted by start index
// (and then by confidence descending) so that earlier, higher-confidence
// matches are preferentially retained.
func dedupEntropyMatches(matches []Match) []Match {
	if len(matches) <= 1 {
		return matches
	}

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Index != matches[j].Index {
			return matches[i].Index < matches[j].Index
		}
		return matches[i].Confidence > matches[j].Confidence
	})

	result := make([]Match, 0, len(matches))
	for _, m := range matches {
		overlapped := false
		for i := range result {
			r := &result[i]
			if m.Index < r.End && m.End > r.Index {
				if m.Confidence > r.Confidence {
					*r = m
				}
				overlapped = true
				break
			}
		}
		if !overlapped {
			result = append(result, m)
		}
	}

	return result
}
