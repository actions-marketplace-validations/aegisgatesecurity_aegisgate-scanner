// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Concurrent Scanning & Disabled Rules Tests
// =========================================================================

package scanner

import (
	"fmt"
	"sort"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/artifacts"
)

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// findingKey produces a deterministic key for comparing findings across runs.
func findingKey(f Finding) string {
	return fmt.Sprintf("%s|%s|%d|%d", f.Artifact, f.RuleID, f.Line, f.Column)
}

// sortFindingKeys returns sorted string keys for a slice of findings.
func sortFindingKeys(findings []Finding) []string {
	keys := make([]string, 0, len(findings))
	for _, f := range findings {
		keys = append(keys, findingKey(f))
	}
	sort.Strings(keys)
	return keys
}

// makeTestArtifacts creates n artifacts; even-indexed ones contain secrets,
// odd-indexed ones are clean.
func makeTestArtifacts(n int) []artifacts.Artifact {
	arts := make([]artifacts.Artifact, n)
	for i := 0; i < n; i++ {
		path := fmt.Sprintf("file_%d.txt", i)
		if i%2 == 0 {
			arts[i] = makeArtifact(path, "AWS_KEY=AKIAIOSFODNN7EXAMPLE\nSSN: 123-45-6789\n")
		} else {
			arts[i] = makeArtifact(path, "This is clean content with no secrets.\n")
		}
	}
	return arts
}

// ---------------------------------------------------------------------
// Disabled Rules tests
// ---------------------------------------------------------------------

func TestScanArtifact_DisabledRules(t *testing.T) {
	s, err := New(ScanOptions{EnableML: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	// Content with an AWS key and an SSN — two different rule IDs.
	content := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\nSSN: 123-45-6789\n"
	art := makeArtifact("test.txt", content)

	// First, scan without disabling anything to get a baseline.
	allFindings := s.ScanArtifact(art, ScanOptions{})
	if len(allFindings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(allFindings))
	}

	// Collect all rule IDs found.
	ruleIDs := make(map[string]bool)
	for _, f := range allFindings {
		ruleIDs[f.RuleID] = true
	}
	if !ruleIDs["secret_aws_key"] {
		t.Fatalf("expected secret_aws_key in findings, got: %v", ruleIDs)
	}

	// Now disable secret_aws_key and verify it's filtered out.
	disabledFindings := s.ScanArtifact(art, ScanOptions{
		DisableRules: []string{"secret_aws_key"},
	})

	for _, f := range disabledFindings {
		if f.RuleID == "secret_aws_key" {
			t.Error("secret_aws_key should have been filtered out by DisableRules")
		}
	}

	// Verify we still have other findings.
	if len(disabledFindings) == 0 {
		t.Error("expected some findings after disabling one rule, got 0")
	}
}

func TestFilterDisabledRules_NoneDisabled(t *testing.T) {
	findings := []Finding{
		{RuleID: "secret_aws_key", Artifact: "a.txt", Line: 1},
		{RuleID: "pii_ssn", Artifact: "b.txt", Line: 2},
		{RuleID: "xss_script_tag", Artifact: "c.txt", Line: 3},
	}

	result := filterDisabledRules(findings, nil)
	if len(result) != 3 {
		t.Errorf("expected 3 findings (nil disabled), got %d", len(result))
	}

	result = filterDisabledRules(findings, []string{})
	if len(result) != 3 {
		t.Errorf("expected 3 findings (empty disabled list), got %d", len(result))
	}
}

func TestFilterDisabledRules_AllDisabled(t *testing.T) {
	findings := []Finding{
		{RuleID: "secret_aws_key", Artifact: "a.txt", Line: 1},
		{RuleID: "pii_ssn", Artifact: "b.txt", Line: 2},
	}

	result := filterDisabledRules(findings, []string{"secret_aws_key", "pii_ssn"})
	if len(result) != 0 {
		t.Errorf("expected 0 findings (all disabled), got %d", len(result))
	}
}

func TestFilterDisabledRules_PartialDisabled(t *testing.T) {
	findings := []Finding{
		{RuleID: "secret_aws_key", Artifact: "a.txt", Line: 1},
		{RuleID: "pii_ssn", Artifact: "b.txt", Line: 2},
		{RuleID: "xss_script_tag", Artifact: "c.txt", Line: 3},
	}

	result := filterDisabledRules(findings, []string{"secret_aws_key"})

	if len(result) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result))
	}
	for _, f := range result {
		if f.RuleID == "secret_aws_key" {
			t.Error("secret_aws_key should have been filtered out")
		}
	}
}

// ---------------------------------------------------------------------
// Concurrent scanning tests
// ---------------------------------------------------------------------

func TestScanArtifacts_Concurrent(t *testing.T) {
	s, err := New(ScanOptions{EnableML: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	arts := makeTestArtifacts(10)
	opts := ScanOptions{Concurrency: 4}

	result := s.ScanArtifacts(arts, opts)

	if result.Stats.FilesScanned != 10 {
		t.Errorf("FilesScanned = %d, want 10", result.Stats.FilesScanned)
	}

	// Even-indexed files (0,2,4,6,8) have findings — 5 files.
	if result.Stats.FilesWithFindings != 5 {
		t.Errorf("FilesWithFindings = %d, want 5", result.Stats.FilesWithFindings)
	}

	if result.Stats.TotalFindings == 0 {
		t.Error("expected some findings, got 0")
	}
}

func TestScanArtifacts_ConcurrentVsSequential(t *testing.T) {
	s, err := New(ScanOptions{EnableML: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	arts := makeTestArtifacts(10)

	// Sequential.
	seqResult := s.ScanArtifacts(arts, ScanOptions{Concurrency: 0})
	// Concurrent.
	conResult := s.ScanArtifacts(arts, ScanOptions{Concurrency: 4})

	// Compare sorted finding keys — order may differ but content must match.
	seqKeys := sortFindingKeys(seqResult.Findings)
	conKeys := sortFindingKeys(conResult.Findings)

	if len(seqKeys) != len(conKeys) {
		t.Fatalf("finding count mismatch: sequential=%d, concurrent=%d", len(seqKeys), len(conKeys))
	}

	for i := range seqKeys {
		if seqKeys[i] != conKeys[i] {
			t.Errorf("finding mismatch at index %d:\n  sequential:  %s\n  concurrent:  %s",
				i, seqKeys[i], conKeys[i])
		}
	}

	// Stats should also match.
	if seqResult.Stats.TotalFindings != conResult.Stats.TotalFindings {
		t.Errorf("TotalFindings mismatch: sequential=%d, concurrent=%d",
			seqResult.Stats.TotalFindings, conResult.Stats.TotalFindings)
	}
	if seqResult.Stats.FilesScanned != conResult.Stats.FilesScanned {
		t.Errorf("FilesScanned mismatch: sequential=%d, concurrent=%d",
			seqResult.Stats.FilesScanned, conResult.Stats.FilesScanned)
	}
}

func TestScanArtifacts_Concurrency1(t *testing.T) {
	s, err := New(ScanOptions{EnableML: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	arts := makeTestArtifacts(10)

	// Concurrency=1 should use sequential path (not >1).
	seqResult := s.ScanArtifacts(arts, ScanOptions{Concurrency: 0})
	c1Result := s.ScanArtifacts(arts, ScanOptions{Concurrency: 1})

	seqKeys := sortFindingKeys(seqResult.Findings)
	c1Keys := sortFindingKeys(c1Result.Findings)

	if len(seqKeys) != len(c1Keys) {
		t.Fatalf("finding count mismatch: sequential=%d, concurrency1=%d", len(seqKeys), len(c1Keys))
	}
	for i := range seqKeys {
		if seqKeys[i] != c1Keys[i] {
			t.Errorf("finding mismatch at index %d: seq=%s, c1=%s", i, seqKeys[i], c1Keys[i])
		}
	}
}

func TestScanArtifacts_Concurrency0(t *testing.T) {
	s, err := New(ScanOptions{EnableML: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	arts := makeTestArtifacts(10)

	// Concurrency=0 means sequential.
	result := s.ScanArtifacts(arts, ScanOptions{Concurrency: 0})

	if result.Stats.FilesScanned != 10 {
		t.Errorf("FilesScanned = %d, want 10", result.Stats.FilesScanned)
	}
	if result.Stats.FilesWithFindings != 5 {
		t.Errorf("FilesWithFindings = %d, want 5", result.Stats.FilesWithFindings)
	}
}

func TestScanArtifacts_LargeSet(t *testing.T) {
	s, err := New(ScanOptions{EnableML: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	arts := makeTestArtifacts(50)
	opts := ScanOptions{Concurrency: 8}

	result := s.ScanArtifacts(arts, opts)

	if result.Stats.FilesScanned != 50 {
		t.Errorf("FilesScanned = %d, want 50", result.Stats.FilesScanned)
	}

	// Even-indexed files (0,2,4,...,48) have findings — 25 files.
	if result.Stats.FilesWithFindings != 25 {
		t.Errorf("FilesWithFindings = %d, want 25", result.Stats.FilesWithFindings)
	}

	if result.Stats.TotalFindings == 0 {
		t.Error("expected some findings, got 0")
	}

	// Verify all artifact paths are represented.
	seenPaths := make(map[string]bool)
	for _, f := range result.Findings {
		seenPaths[f.Artifact] = true
	}
	expectedPaths := 25 // even-indexed files
	if len(seenPaths) != expectedPaths {
		t.Errorf("unique artifact paths with findings = %d, want %d", len(seenPaths), expectedPaths)
	}
}

// ---------------------------------------------------------------------
// Bonus: Concurrency > number of artifacts (extra coverage)
// ---------------------------------------------------------------------

func TestScanArtifacts_ConcurrencyExceedsArtifacts(t *testing.T) {
	s, err := New(ScanOptions{EnableML: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	arts := makeTestArtifacts(2)
	result := s.ScanArtifacts(arts, ScanOptions{Concurrency: 8})

	if result.Stats.FilesScanned != 2 {
		t.Errorf("FilesScanned = %d, want 2", result.Stats.FilesScanned)
	}
}

// ---------------------------------------------------------------------
// Bonus: Single artifact with concurrency > 1 (extra coverage)
// ---------------------------------------------------------------------

func TestScanArtifacts_SingleArtifactConcurrent(t *testing.T) {
	s, err := New(ScanOptions{EnableML: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	arts := []artifacts.Artifact{
		makeArtifact("single.txt", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"),
	}
	// Concurrency > 1 but len(arts) == 1, so should use sequential.
	result := s.ScanArtifacts(arts, ScanOptions{Concurrency: 4})

	if result.Stats.FilesScanned != 1 {
		t.Errorf("FilesScanned = %d, want 1", result.Stats.FilesScanned)
	}
	if result.Stats.TotalFindings == 0 {
		t.Error("expected findings, got 0")
	}
}

// ---------------------------------------------------------------------
// Bonus: Empty artifacts slice (extra coverage)
// ---------------------------------------------------------------------

func TestScanArtifacts_EmptyArtifacts(t *testing.T) {
	s, err := New(ScanOptions{EnableML: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	result := s.ScanArtifacts(nil, ScanOptions{Concurrency: 4})
	if result.Stats.FilesScanned != 0 {
		t.Errorf("FilesScanned = %d, want 0", result.Stats.FilesScanned)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

// ---------------------------------------------------------------------
// Bonus: filterDisabledRules with unknown rule IDs (extra coverage)
// ---------------------------------------------------------------------

func TestFilterDisabledRules_UnknownRule(t *testing.T) {
	findings := []Finding{
		{RuleID: "secret_aws_key", Artifact: "a.txt", Line: 1},
		{RuleID: "pii_ssn", Artifact: "b.txt", Line: 2},
	}

	// Disabling a rule that doesn't exist in findings should be a no-op.
	result := filterDisabledRules(findings, []string{"nonexistent_rule"})
	if len(result) != 2 {
		t.Errorf("expected 2 findings (unknown disabled rule), got %d", len(result))
	}
}

// ---------------------------------------------------------------------
// Bonus: filterBySeverity with unknown severity (extra coverage)
// ---------------------------------------------------------------------

func TestFilterBySeverity_UnknownSeverity(t *testing.T) {
	findings := []Finding{
		{RuleID: "secret_aws_key", Severity: "critical"},
		{RuleID: "pii_ssn", Severity: "high"},
	}

	// Unknown min severity should not filter anything.
	result := filterBySeverity(findings, "unknown")
	if len(result) != 2 {
		t.Errorf("expected 2 findings (unknown min severity), got %d", len(result))
	}
}

// ---------------------------------------------------------------------
// Bonus: ScanArtifact with MaxFindingsPerFile (extra coverage)
// ---------------------------------------------------------------------

func TestScanArtifact_MaxFindingsPerFile_Features(t *testing.T) {
	s, err := New(ScanOptions{EnableML: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	content := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\nSSN: 123-45-6789\nPhone: 555-123-4567\n"
	art := makeArtifact("test.txt", content)

	findings := s.ScanArtifact(art, ScanOptions{MaxFindingsPerFile: 1})
	if len(findings) != 1 {
		t.Errorf("expected 1 finding (MaxFindingsPerFile=1), got %d", len(findings))
	}
}
