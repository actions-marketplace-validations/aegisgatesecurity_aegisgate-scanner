// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Baseline Suppression Tests
// =========================================================================

package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/scanner"
)

// ---------------------------------------------------------------------
// Load tests
// ---------------------------------------------------------------------

func TestLoad_NonexistentFile(t *testing.T) {
	bl, err := Load(filepath.Join(t.TempDir(), "nonexistent.json"))
	if err != nil {
		t.Fatalf("Load returned error for nonexistent file: %v", err)
	}
	if bl == nil {
		t.Fatal("Load returned nil baseline")
	}
	if len(bl.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(bl.Entries))
	}
}

func TestLoad_EmptyPath(t *testing.T) {
	bl, err := Load("")
	if err != nil {
		t.Fatalf("Load returned error for empty path: %v", err)
	}
	if bl == nil {
		t.Fatal("Load returned nil baseline")
	}
	if len(bl.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(bl.Entries))
	}
}

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	data := Baseline{
		Version: Version,
		Entries: []Entry{
			{RuleID: "secret_aws_key", Artifact: "config.yml", Line: 42},
			{RuleID: "pii_ssn", Artifact: "data.txt", Line: 10},
		},
	}
	raw, _ := json.MarshalIndent(data, "", "  ")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	bl, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(bl.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(bl.Entries))
	}
	if bl.Entries[0].RuleID != "secret_aws_key" {
		t.Errorf("entry[0] RuleID = %s, want secret_aws_key", bl.Entries[0].RuleID)
	}
	if bl.Entries[0].Artifact != "config.yml" {
		t.Errorf("entry[0] Artifact = %s, want config.yml", bl.Entries[0].Artifact)
	}
	if bl.Entries[0].Line != 42 {
		t.Errorf("entry[0] Line = %d, want 42", bl.Entries[0].Line)
	}
	if bl.Entries[1].RuleID != "pii_ssn" {
		t.Errorf("entry[1] RuleID = %s, want pii_ssn", bl.Entries[1].RuleID)
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{invalid json}}}"), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	bl, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
	if bl != nil {
		t.Errorf("expected nil baseline on error, got %+v", bl)
	}
}

func TestLoad_VersionMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	data := Baseline{
		Version: 2, // wrong version
		Entries: []Entry{
			{RuleID: "secret_aws_key", Artifact: "config.yml", Line: 42},
		},
	}
	raw, _ := json.MarshalIndent(data, "", "  ")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	bl, err := Load(path)
	if err == nil {
		t.Error("expected error for version mismatch, got nil")
	}
	if bl != nil {
		t.Errorf("expected nil baseline on error, got %+v", bl)
	}
}

// ---------------------------------------------------------------------
// Save tests
// ---------------------------------------------------------------------

func TestSave_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	bl := &Baseline{
		Entries: []Entry{
			{RuleID: "secret_aws_key", Artifact: "config.yml", Line: 42},
		},
	}

	if err := bl.Save(path); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	// Verify file exists.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("file does not exist after Save: %v", err)
	}
	if info.Size() == 0 {
		t.Error("file is empty after Save")
	}

	// Verify file is valid JSON and can be loaded.
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("failed to load saved file: %v", err)
	}
	if loaded.Version != Version {
		t.Errorf("loaded Version = %d, want %d", loaded.Version, Version)
	}
	if len(loaded.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(loaded.Entries))
	}
	if loaded.Entries[0].RuleID != "secret_aws_key" {
		t.Errorf("entry RuleID = %s, want secret_aws_key", loaded.Entries[0].RuleID)
	}
}

func TestSave_SortedEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	bl := &Baseline{
		Entries: []Entry{
			{RuleID: "pii_ssn", Artifact: "zfile.txt", Line: 5},
			{RuleID: "secret_aws_key", Artifact: "config.yml", Line: 42},
			{RuleID: "pii_ssn", Artifact: "afile.txt", Line: 10},
			{RuleID: "pii_ssn", Artifact: "afile.txt", Line: 3},
		},
	}

	if err := bl.Save(path); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("failed to load saved file: %v", err)
	}

	// Verify entries are sorted by artifact, then rule_id, then line.
	expected := []Entry{
		{RuleID: "pii_ssn", Artifact: "afile.txt", Line: 3},
		{RuleID: "pii_ssn", Artifact: "afile.txt", Line: 10},
		{RuleID: "secret_aws_key", Artifact: "config.yml", Line: 42},
		{RuleID: "pii_ssn", Artifact: "zfile.txt", Line: 5},
	}

	if len(loaded.Entries) != len(expected) {
		t.Fatalf("expected %d entries, got %d", len(expected), len(loaded.Entries))
	}

	for i, e := range loaded.Entries {
		if e.Artifact != expected[i].Artifact || e.RuleID != expected[i].RuleID || e.Line != expected[i].Line {
			t.Errorf("entry[%d] = {%s, %s, %d}, want {%s, %s, %d}",
				i, e.Artifact, e.RuleID, e.Line,
				expected[i].Artifact, expected[i].RuleID, expected[i].Line)
		}
	}
}

// ---------------------------------------------------------------------
// FromScanResult tests
// ---------------------------------------------------------------------

func TestFromScanResult(t *testing.T) {
	result := &scanner.ScanResult{
		Findings: []scanner.Finding{
			{RuleID: "secret_aws_key", Artifact: "config.yml", Line: 42, Severity: scanner.Severity("critical")},
			{RuleID: "pii_ssn", Artifact: "data.txt", Line: 10, Severity: scanner.Severity("high")},
			{RuleID: "pii_email", Artifact: "contacts.txt", Line: 3, Severity: scanner.Severity("medium")},
		},
	}

	bl := FromScanResult(result)
	if bl == nil {
		t.Fatal("FromScanResult returned nil")
	}
	if bl.Version != Version {
		t.Errorf("Version = %d, want %d", bl.Version, Version)
	}
	if len(bl.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(bl.Entries))
	}

	for i, f := range result.Findings {
		e := bl.Entries[i]
		if e.RuleID != f.RuleID {
			t.Errorf("entry[%d] RuleID = %s, want %s", i, e.RuleID, f.RuleID)
		}
		if e.Artifact != f.Artifact {
			t.Errorf("entry[%d] Artifact = %s, want %s", i, e.Artifact, f.Artifact)
		}
		if e.Line != f.Line {
			t.Errorf("entry[%d] Line = %d, want %d", i, e.Line, f.Line)
		}
	}
}

// ---------------------------------------------------------------------
// IsSuppressed tests
// ---------------------------------------------------------------------

func TestIsSuppressed_Match(t *testing.T) {
	bl := &Baseline{
		Entries: []Entry{
			{RuleID: "secret_aws_key", Artifact: "config.yml", Line: 42},
		},
	}

	if !bl.IsSuppressed("secret_aws_key", "config.yml", 42) {
		t.Error("expected finding to be suppressed")
	}
}

func TestIsSuppressed_NoMatch(t *testing.T) {
	bl := &Baseline{
		Entries: []Entry{
			{RuleID: "secret_aws_key", Artifact: "config.yml", Line: 42},
		},
	}

	if bl.IsSuppressed("pii_ssn", "config.yml", 42) {
		t.Error("expected finding NOT to be suppressed (different rule_id)")
	}
	if bl.IsSuppressed("secret_aws_key", "other.yml", 42) {
		t.Error("expected finding NOT to be suppressed (different artifact)")
	}
	if bl.IsSuppressed("secret_aws_key", "config.yml", 99) {
		t.Error("expected finding NOT to be suppressed (different line)")
	}
}

func TestIsSuppressed_NilBaseline(t *testing.T) {
	var bl *Baseline
	if bl.IsSuppressed("secret_aws_key", "config.yml", 42) {
		t.Error("expected false for nil baseline")
	}
}

// ---------------------------------------------------------------------
// Filter tests
// ---------------------------------------------------------------------

func TestFilter_AllSuppressed(t *testing.T) {
	bl := &Baseline{
		Entries: []Entry{
			{RuleID: "secret_aws_key", Artifact: "config.yml", Line: 42},
			{RuleID: "pii_ssn", Artifact: "data.txt", Line: 10},
		},
	}

	findings := []scanner.Finding{
		{RuleID: "secret_aws_key", Artifact: "config.yml", Line: 42},
		{RuleID: "pii_ssn", Artifact: "data.txt", Line: 10},
	}

	filtered, suppressed := bl.Filter(findings)
	if len(filtered) != 0 {
		t.Errorf("expected 0 filtered findings, got %d", len(filtered))
	}
	if suppressed != 2 {
		t.Errorf("expected 2 suppressed, got %d", suppressed)
	}
}

func TestFilter_NoneSuppressed(t *testing.T) {
	bl := &Baseline{
		Entries: []Entry{
			{RuleID: "secret_aws_key", Artifact: "config.yml", Line: 42},
		},
	}

	findings := []scanner.Finding{
		{RuleID: "pii_ssn", Artifact: "data.txt", Line: 10},
		{RuleID: "pii_email", Artifact: "contacts.txt", Line: 3},
	}

	filtered, suppressed := bl.Filter(findings)
	if len(filtered) != 2 {
		t.Errorf("expected 2 filtered findings, got %d", len(filtered))
	}
	if suppressed != 0 {
		t.Errorf("expected 0 suppressed, got %d", suppressed)
	}
}

func TestFilter_PartialSuppression(t *testing.T) {
	bl := &Baseline{
		Entries: []Entry{
			{RuleID: "secret_aws_key", Artifact: "config.yml", Line: 42},
		},
	}

	findings := []scanner.Finding{
		{RuleID: "secret_aws_key", Artifact: "config.yml", Line: 42},  // suppressed
		{RuleID: "pii_ssn", Artifact: "data.txt", Line: 10},           // not suppressed
		{RuleID: "secret_aws_key", Artifact: "config.yml", Line: 100}, // not suppressed (different line)
	}

	filtered, suppressed := bl.Filter(findings)
	if len(filtered) != 2 {
		t.Errorf("expected 2 filtered findings, got %d", len(filtered))
	}
	if suppressed != 1 {
		t.Errorf("expected 1 suppressed, got %d", suppressed)
	}

	// Verify the remaining findings are the non-suppressed ones.
	for _, f := range filtered {
		if f.RuleID == "secret_aws_key" && f.Artifact == "config.yml" && f.Line == 42 {
			t.Error("suppressed finding was not filtered out")
		}
	}
}

func TestFilter_NilBaseline(t *testing.T) {
	var bl *Baseline

	findings := []scanner.Finding{
		{RuleID: "secret_aws_key", Artifact: "config.yml", Line: 42},
		{RuleID: "pii_ssn", Artifact: "data.txt", Line: 10},
	}

	filtered, suppressed := bl.Filter(findings)
	if len(filtered) != 2 {
		t.Errorf("expected all 2 findings returned, got %d", len(filtered))
	}
	if suppressed != 0 {
		t.Errorf("expected 0 suppressed, got %d", suppressed)
	}
}

func TestFilter_EmptyBaseline(t *testing.T) {
	bl := &Baseline{
		Entries: []Entry{},
	}

	findings := []scanner.Finding{
		{RuleID: "secret_aws_key", Artifact: "config.yml", Line: 42},
		{RuleID: "pii_ssn", Artifact: "data.txt", Line: 10},
	}

	filtered, suppressed := bl.Filter(findings)
	if len(filtered) != 2 {
		t.Errorf("expected all 2 findings returned, got %d", len(filtered))
	}
	if suppressed != 0 {
		t.Errorf("expected 0 suppressed, got %d", suppressed)
	}
}

// ---------------------------------------------------------------------
// Round-trip test (bonus coverage)
// ---------------------------------------------------------------------

func TestSaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	original := &Baseline{
		Entries: []Entry{
			{RuleID: "rule_c", Artifact: "c.txt", Line: 3},
			{RuleID: "rule_a", Artifact: "a.txt", Line: 1},
			{RuleID: "rule_a", Artifact: "a.txt", Line: 5},
		},
	}

	if err := original.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(loaded.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(loaded.Entries))
	}

	// Verify sorted order: a.txt:rule_a:1, a.txt:rule_a:5, c.txt:rule_c:3
	expected := []Entry{
		{RuleID: "rule_a", Artifact: "a.txt", Line: 1},
		{RuleID: "rule_a", Artifact: "a.txt", Line: 5},
		{RuleID: "rule_c", Artifact: "c.txt", Line: 3},
	}
	for i, e := range loaded.Entries {
		if e != expected[i] {
			t.Errorf("entry[%d] = %+v, want %+v", i, e, expected[i])
		}
	}
}

// ---------------------------------------------------------------------
// FromScanResult + Filter integration test (bonus coverage)
// ---------------------------------------------------------------------

func TestFromScanResult_AndFilter_Integration(t *testing.T) {
	result := &scanner.ScanResult{
		Findings: []scanner.Finding{
			{RuleID: "secret_aws_key", Artifact: "config.yml", Line: 42},
			{RuleID: "pii_ssn", Artifact: "data.txt", Line: 10},
		},
	}

	bl := FromScanResult(result)

	// All original findings should be suppressed.
	filtered, suppressed := bl.Filter(result.Findings)
	if len(filtered) != 0 {
		t.Errorf("expected 0 filtered, got %d", len(filtered))
	}
	if suppressed != 2 {
		t.Errorf("expected 2 suppressed, got %d", suppressed)
	}

	// A new finding should NOT be suppressed.
	newFindings := append(result.Findings, scanner.Finding{
		RuleID: "pii_email", Artifact: "new.txt", Line: 1,
	})
	filtered, suppressed = bl.Filter(newFindings)
	if len(filtered) != 1 {
		t.Errorf("expected 1 filtered (new finding), got %d", len(filtered))
	}
	if suppressed != 2 {
		t.Errorf("expected 2 suppressed, got %d", suppressed)
	}
}

// ---------------------------------------------------------------------
// Sorted entries helper test (bonus coverage for Save sorting logic)
// ---------------------------------------------------------------------

func TestSave_EmptyEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	bl := &Baseline{Entries: []Entry{}}
	if err := bl.Save(path); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(loaded.Entries))
	}
}

// ---------------------------------------------------------------------
// IsSuppressed with empty entries (bonus coverage)
// ---------------------------------------------------------------------

func TestIsSuppressed_EmptyEntries(t *testing.T) {
	bl := &Baseline{Entries: []Entry{}}
	if bl.IsSuppressed("secret_aws_key", "config.yml", 42) {
		t.Error("expected false for empty entries")
	}
}

// ---------------------------------------------------------------------
// Ensure sorted entries from FromScanResult via Save (bonus coverage)
// ---------------------------------------------------------------------

func TestFromScanResult_Save_Sorted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	result := &scanner.ScanResult{
		Findings: []scanner.Finding{
			{RuleID: "z_rule", Artifact: "z.txt", Line: 1},
			{RuleID: "a_rule", Artifact: "a.txt", Line: 5},
			{RuleID: "a_rule", Artifact: "a.txt", Line: 2},
		},
	}

	bl := FromScanResult(result)
	if err := bl.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Verify sorted.
	artifacts := make([]string, len(loaded.Entries))
	for i, e := range loaded.Entries {
		artifacts[i] = e.Artifact
	}
	if !sort.StringsAreSorted(artifacts) {
		t.Errorf("entries not sorted by artifact: %v", artifacts)
	}
}
