// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Known Example Value Suppression
// =========================================================================
//
// Automatically suppresses findings that match known documentation examples,
// test fixtures, and placeholder values. This eliminates the noise of
// flagging AWS documentation keys, GitHub test tokens, and other well-known
// example values that appear in tutorials, SDKs, and test files.
//
// Suppressed findings have their confidence reduced to 0.1 rather than
// being silently dropped — they remain visible in verbose output but
// won't trigger CI failures.
//
// =========================================================================

package detectors

import "strings"

// KnownExampleValues is a set of known example/test values that should be
// suppressed. Lookups are case-sensitive.
var KnownExampleValues = map[string]bool{
	// AWS documentation examples
	"AKIAIOSFODNN7EXAMPLE":                     true,
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": true,

	// GitHub test tokens (all prefix variants with sequential placeholder body)
	"ghp_0123456789012345678901234567890123456789": true,
	"gho_0123456789012345678901234567890123456789": true,
	"ghs_0123456789012345678901234567890123456789": true,
	"ghu_0123456789012345678901234567890123456789": true,

	// Google example API key
	"AIzaSyD_fake_api_key_for_testing_0123456789": true,

	// Azure example connection string
	"DefaultEndpointsProtocol=https;AccountName=example;AccountKey=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF==": true,

	// Slack test token
	"xoxb-0000000000-0000000000-000000000000000000000000": true,

	// Twilio test API key
	"SK00000000000000000000000000000000": true,

	// Stripe test keys
	"sk_test_1234567890abcdefghijklmnopqrstuvwxyz": true,
	"pk_test_1234567890abcdefghijklmnopqrstuvwxyz": true,

	// JWT example (from jwt.io)
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c": true,

	// Generic placeholder values
	"example_api_key_12345":       true,
	"test_token_abcdef":           true,
	"dummy_secret_1234567890":     true,
	"placeholder_key_value_12345": true,

	// Common test/fixture values
	"1234567890abcdef1234567890abcdef12345678": true,
	"testtesttesttesttesttesttesttesttesttest": true,
}

// KnownExamplePrefixes are prefixes that indicate an example or test value.
// Matching is case-sensitive.
var KnownExamplePrefixes = []string{
	"AKIAIOSFODNN7",
	"wJalrXUtnFEMI",
	"ghp_0123456789",
	"gho_0123456789",
	"ghs_0123456789",
	"ghu_0123456789",
	"sk_test_",
	"pk_test_",
	"xoxb-0000000000",
	"xoxp-0000000000",
	"AIzaSyD_fake",
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkw",
}

// knownExampleKeywords are common test/example indicators that are matched
// case-insensitively against the full value.
var knownExampleKeywords = []string{
	"example",
	"test",
	"dummy",
	"placeholder",
	"fake",
	"sample",
	"demo",
}

// IsKnownExample returns true if the value matches any known example value
// exactly, starts with any known example prefix, or contains (case-insensitively)
// any common test/example keyword.
func IsKnownExample(value string) bool {
	if value == "" {
		return false
	}

	// Exact match against known values.
	if KnownExampleValues[value] {
		return true
	}

	// Prefix match against known prefixes.
	for _, prefix := range KnownExamplePrefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}

	// Private key example block — check the well-known PEM header prefix.
	if strings.HasPrefix(value, "-----BEGIN RSA PRIVATE KEY-----") {
		return true
	}

	// Case-insensitive keyword check for common test indicators.
	lower := strings.ToLower(value)
	for _, kw := range knownExampleKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}

	return false
}

// IsExampleByContent returns true if the value contains common test/example
// indicators: known keywords, repeated numeric sequences, all-same-character
// values, or sequential character runs (abcdef, 123456). This catches values
// that aren't in the explicit list but are obviously test data.
func IsExampleByContent(value string) bool {
	if value == "" {
		return false
	}

	// Delegate keyword / prefix / exact checks to IsKnownExample first so we
	// get consistent behaviour, then add heuristics unique to content analysis.
	if IsKnownExample(value) {
		return true
	}

	// "0123456789" repeated indicates a placeholder numeric body.
	if strings.Contains(value, "01234567890123456789") {
		return true
	}

	// All characters identical (e.g. "aaaaaa", "000000").
	if isAllSameChar(value) {
		return true
	}

	// Sequential ascending or descending character runs of length >= 6.
	if hasSequentialRun(value, 6) {
		return true
	}

	return false
}

// isAllSameChar reports whether every byte in s is identical. Values of
// length < 2 are not considered "all same" (a single char is trivially real).
func isAllSameChar(s string) bool {
	if len(s) < 2 {
		return false
	}
	first := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != first {
			return false
		}
	}
	return true
}

// hasSequentialRun reports whether s contains a run of at least minLen
// consecutive ascending or descending ASCII characters (e.g. "abcdef",
// "123456", "fedcba", "987654").
func hasSequentialRun(s string, minLen int) bool {
	if len(s) < minLen {
		return false
	}

	run := 1
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1]+1 {
			// ascending
			run++
			if run >= minLen {
				return true
			}
		} else if s[i] == s[i-1]-1 {
			// descending
			run++
			if run >= minLen {
				return true
			}
		} else {
			run = 1
		}
	}
	return false
}

// FilterKnownExamples separates matches into kept (real findings) and
// suppressed (known examples). Suppressed matches have their Confidence
// reduced to 0.1.
func FilterKnownExamples(matches []Match) (kept []Match, suppressed []Match) {
	kept = make([]Match, 0, len(matches))
	suppressed = make([]Match, 0, len(matches))

	for _, m := range matches {
		if IsKnownExample(m.Value) || IsExampleByContent(m.Value) {
			m.Confidence = 0.1
			suppressed = append(suppressed, m)
		} else {
			kept = append(kept, m)
		}
	}
	return kept, suppressed
}

// SuppressExamples is a convenience wrapper around FilterKnownExamples that
// returns only the non-example (kept) matches.
func SuppressExamples(matches []Match) []Match {
	kept, _ := FilterKnownExamples(matches)
	return kept
}
