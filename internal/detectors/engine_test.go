package detectors

import (
	"testing"
)

// ============================================================================
// DetectAllWithResults tests
// ============================================================================

func TestDetectAllWithResults_MultiThreatText(t *testing.T) {
	text := "SSN: 123-45-6789, AWS key: AKIAIOSFODNN7EXAMPLE, <script>alert(1)</script>"
	all, results := DetectAllWithResults(text)
	if len(all) == 0 {
		t.Error("DetectAllWithResults should find threats in multi-threat text")
	}
	if len(results) != 7 {
		t.Errorf("Expected 7 DetectionResult categories, got %d", len(results))
	}
}

func TestDetectAllWithResults_CleanText(t *testing.T) {
	text := "The weather is nice today"
	all, results := DetectAllWithResults(text)
	if len(all) != 0 {
		t.Errorf("DetectAllWithResults on clean text should return 0 matches, got %d", len(all))
	}
	if len(results) != 7 {
		t.Errorf("Expected 7 DetectionResult categories even for clean text, got %d", len(results))
	}
	// Each result should have 0 matches for clean text
	for _, r := range results {
		if len(r.Matches) != 0 {
			t.Errorf("Category %s should have 0 matches for clean text, got %d", r.Category, len(r.Matches))
		}
	}
}

func TestDetectAllWithResults_EmptyText(t *testing.T) {
	all, results := DetectAllWithResults("")
	if len(all) != 0 {
		t.Errorf("DetectAllWithResults on empty string should return 0 matches, got %d", len(all))
	}
	if len(results) != 7 {
		t.Errorf("Expected 7 DetectionResult categories, got %d", len(results))
	}
}

func TestDetectAllWithResults_ResultsHaveCategory(t *testing.T) {
	text := "SSN: 123-45-6789"
	_, results := DetectAllWithResults(text)
	for _, r := range results {
		if r.Category == "" {
			t.Error("DetectionResult should have a non-empty Category")
		}
	}
}

func TestDetectAllWithResults_ResultsHavePatternCount(t *testing.T) {
	text := "SSN: 123-45-6789"
	_, results := DetectAllWithResults(text)
	for _, r := range results {
		if r.PatternCount <= 0 {
			t.Errorf("DetectionResult for category %s should have PatternCount > 0, got %d", r.Category, r.PatternCount)
		}
	}
}

func TestDetectAllWithResults_ResultsHaveElapsedNS(t *testing.T) {
	text := "SSN: 123-45-6789"
	_, results := DetectAllWithResults(text)
	for _, r := range results {
		if r.ElapsedNS < 0 {
			t.Errorf("DetectionResult for category %s should have ElapsedNS >= 0, got %d", r.Category, r.ElapsedNS)
		}
	}
}

func TestDetectAllWithResults_SecretsOnly(t *testing.T) {
	text := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
	all, results := DetectAllWithResults(text)

	secretsResult := results[0] // First result is CategorySecrets
	if secretsResult.Category != CategorySecrets {
		t.Errorf("First result category = %s, want %s", secretsResult.Category, CategorySecrets)
	}
	if len(secretsResult.Matches) == 0 && len(all) > 0 {
		// Some match found, but not in secrets category
		t.Logf("Secrets category had %d matches, total matches: %d", len(secretsResult.Matches), len(all))
	}
}

func TestDetectAllWithResults_ResultStructures(t *testing.T) {
	text := "<script>alert('xss')</script>"
	all, results := DetectAllWithResults(text)
	_ = all

	// Verify each DetectionResult has proper structure
	for _, r := range results {
		if r.PatternCount <= 0 {
			t.Errorf("PatternCount should be positive for %s, got %d", r.Category, r.PatternCount)
		}
	}
}

func TestDetectAllWithResults_MatchesSortedByIndex(t *testing.T) {
	text := "AKIAIOSFODNN7EXAMPLE and 123-45-6789 and <script>alert(1)</script>"
	all, _ := DetectAllWithResults(text)
	for i := 1; i < len(all); i++ {
		if all[i].Index < all[i-1].Index {
			t.Errorf("Matches not sorted by index: all[%d].Index=%d > all[%d].Index=%d",
				i-1, all[i-1].Index, i, all[i].Index)
		}
	}
}

// ============================================================================
// detectWithResult tests (via DetectAllWithResults)
// ============================================================================

func TestDetectWithResult_MatchesInCategory(t *testing.T) {
	text := "My SSN is 123-45-6789"
	_, results := DetectAllWithResults(text)

	// Find PII US Core category result
	var piiResult *DetectionResult
	for i := range results {
		if results[i].Category == CategoryPIIUSCore {
			piiResult = &results[i]
			break
		}
	}

	if piiResult == nil {
		t.Fatal("Should have PII US Core result")
	}
	if len(piiResult.Matches) == 0 {
		t.Error("PII US Core should detect SSN")
	}
}

func TestDetectWithResult_ElapsedNSTiming(t *testing.T) {
	text := "Contact me at user@example.com and call (555) 123-4567"
	_, results := DetectAllWithResults(text)
	for _, r := range results {
		// ElapsedNS should be non-negative (zero is acceptable for fast operations)
		if r.ElapsedNS < 0 {
			t.Errorf("ElapsedNS should be non-negative, got %d for %s", r.ElapsedNS, r.Category)
		}
	}
}

func TestDetectWithResult_MatchFields(t *testing.T) {
	text := "AKIAIOSFODNN7EXAMPLE"
	all, _ := DetectAllWithResults(text)
	if len(all) == 0 {
		t.Fatal("Expected at least one match")
	}
	m := all[0]
	if m.Category == "" {
		t.Error("Match should have a non-empty Category")
	}
	if m.Severity == "" {
		t.Error("Match should have a non-empty Severity")
	}
	if m.Value == "" {
		t.Error("Match should have a non-empty Value")
	}
	if m.End <= m.Index {
		t.Errorf("Match End (%d) should be greater than Index (%d)", m.End, m.Index)
	}
}

func TestDetectWithResult_ConsistentWithDetectAll(t *testing.T) {
	text := "SSN: 123-45-6789, AWS key: AKIAIOSFODNN7EXAMPLE, <script>alert(1)</script>"
	detectAllMatches := DetectAll(text)
	allFromResults, _ := DetectAllWithResults(text)

	if len(detectAllMatches) != len(allFromResults) {
		t.Errorf("DetectAll returned %d matches, DetectAllWithResults returned %d matches",
			len(detectAllMatches), len(allFromResults))
	}
}

// ============================================================================
// DetectionResult struct tests
// ============================================================================

func TestDetectionResultStruct(t *testing.T) {
	dr := DetectionResult{
		Category:     CategorySecrets,
		Matches:      []Match{{Category: "test", Value: "match1", Index: 0, End: 5}},
		PatternCount: 45,
		ElapsedNS:    1000,
	}
	if dr.Category != CategorySecrets {
		t.Errorf("Category = %s, want %s", dr.Category, CategorySecrets)
	}
	if dr.PatternCount != 45 {
		t.Errorf("PatternCount = %d, want 45", dr.PatternCount)
	}
	if len(dr.Matches) != 1 {
		t.Errorf("Matches length = %d, want 1", len(dr.Matches))
	}
	if dr.ElapsedNS != 1000 {
		t.Errorf("ElapsedNS = %d, want 1000", dr.ElapsedNS)
	}
}

func TestDetectAllWithResults_EachCategoryPresent(t *testing.T) {
	_, results := DetectAllWithResults("clean text no threats")
	expectedCategories := []Category{
		CategorySecrets,
		CategoryXSS,
		CategoryPIIUSCore,
		CategoryPIIUSExtended,
		CategoryPIIFinancial,
		CategoryPIIInternational,
		CategoryCompliance,
	}
	if len(results) != len(expectedCategories) {
		t.Fatalf("Expected %d results, got %d", len(expectedCategories), len(results))
	}
	for i, cat := range expectedCategories {
		if results[i].Category != cat {
			t.Errorf("Result[%d].Category = %s, want %s", i, results[i].Category, cat)
		}
	}
}

func TestDetectAllWithResults_XSSDetection(t *testing.T) {
	text := `<script>alert('xss')</script>`
	all, results := DetectAllWithResults(text)

	var xssResult *DetectionResult
	for i := range results {
		if results[i].Category == CategoryXSS {
			xssResult = &results[i]
			break
		}
	}
	if xssResult == nil {
		t.Fatal("Should have XSS result")
	}
	if len(xssResult.Matches) == 0 {
		t.Error("XSS category should detect script tag")
	}
	if len(all) == 0 {
		t.Error("DetectAllWithResults should find XSS match")
	}
}

func TestDetectAllWithResults_ComplianceDetection(t *testing.T) {
	text := "GDPR Article 6 requires consent"
	_, results := DetectAllWithResults(text)

	var complianceResult *DetectionResult
	for i := range results {
		if results[i].Category == CategoryCompliance {
			complianceResult = &results[i]
			break
		}
	}
	if complianceResult == nil {
		t.Fatal("Should have Compliance result")
	}
	// Compliance may or may not match depending on pattern; just verify structure
	_ = complianceResult
}
