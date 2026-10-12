// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — API/SDK Tests
// =========================================================================
//
// Tests for the programmatic API: NewScanner, ScanPath, ScanContent,
// ScanReader, ScanFiles, and edge cases.
//
// =========================================================================

package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------
// NewScanner tests
// ---------------------------------------------------------------------

func TestNewScanner(t *testing.T) {
	sc, err := NewScanner()
	if err != nil {
		t.Fatalf("NewScanner error: %v", err)
	}
	defer sc.Close()

	if sc == nil {
		t.Fatal("scanner should not be nil")
	}
}

func TestNewScannerWithOptions(t *testing.T) {
	sc, err := NewScannerWithOptions(ScannerOptions{
		EnableML:           false,
		MinSeverity:        "high",
		MaxFindingsPerFile: 10,
		Concurrency:        2,
	})
	if err != nil {
		t.Fatalf("NewScannerWithOptions error: %v", err)
	}
	defer sc.Close()
}

func TestNewScannerWithOptions_EmptySeverity(t *testing.T) {
	sc, err := NewScannerWithOptions(ScannerOptions{
		MinSeverity: "",
	})
	if err != nil {
		t.Fatalf("NewScannerWithOptions error: %v", err)
	}
	defer sc.Close()
}

// ---------------------------------------------------------------------
// ScanPath tests
// ---------------------------------------------------------------------

func TestScanPath_Basic(t *testing.T) {
	dir := t.TempDir()

	// Create a file with a secret.
	os.WriteFile(filepath.Join(dir, "config.yaml"),
		[]byte("aws_key: AKIAIOSFODNN7EXAMPLE\n"), 0644)

	sc, _ := NewScanner()
	defer sc.Close()

	result, err := sc.ScanPath(dir)
	if err != nil {
		t.Fatalf("ScanPath error: %v", err)
	}

	if result.Stats.FilesScanned == 0 {
		t.Error("expected at least 1 file scanned")
	}

	// Should find the AWS key.
	if result.Stats.TotalFindings == 0 {
		t.Error("expected at least 1 finding for AWS key")
	}
}

func TestScanPath_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	sc, _ := NewScanner()
	defer sc.Close()

	result, err := sc.ScanPath(dir)
	if err != nil {
		t.Fatalf("ScanPath error: %v", err)
	}

	if result.Stats.TotalFindings != 0 {
		t.Errorf("expected 0 findings in empty dir, got %d", result.Stats.TotalFindings)
	}
}

func TestScanPath_EmptyPath(t *testing.T) {
	sc, _ := NewScanner()
	defer sc.Close()

	_, err := sc.ScanPath("")
	if err == nil {
		t.Error("ScanPath should error on empty path")
	}
}

func TestScanPath_NonExistent(t *testing.T) {
	sc, _ := NewScanner()
	defer sc.Close()

	// Non-existent path: Walk returns empty result, not an error.
	result, err := sc.ScanPath("/nonexistent/path/12345")
	if err != nil {
		t.Fatalf("ScanPath should not error on non-existent path: %v", err)
	}
	if result.Stats.FilesScanned != 0 {
		t.Errorf("expected 0 files scanned for non-existent, got %d", result.Stats.FilesScanned)
	}
}

// ---------------------------------------------------------------------
// ScanContent tests
// ---------------------------------------------------------------------

func TestScanContent_Basic(t *testing.T) {
	sc, _ := NewScanner()
	defer sc.Close()

	content := []byte("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
	result, err := sc.ScanContent("config.yaml", content)
	if err != nil {
		t.Fatalf("ScanContent error: %v", err)
	}

	if result.Stats.TotalFindings == 0 {
		t.Error("expected at least 1 finding")
	}

	// Check finding details.
	for _, f := range result.Findings {
		if f.Artifact != "config.yaml" {
			t.Errorf("artifact = %s, want config.yaml", f.Artifact)
		}
	}
}

func TestScanContent_NoFindings(t *testing.T) {
	sc, _ := NewScanner()
	defer sc.Close()

	content := []byte("just some regular text without any secrets\n")
	result, err := sc.ScanContent("safe.txt", content)
	if err != nil {
		t.Fatalf("ScanContent error: %v", err)
	}

	if result.Stats.TotalFindings != 0 {
		t.Errorf("expected 0 findings, got %d", result.Stats.TotalFindings)
	}
}

func TestScanContent_EmptyFilename(t *testing.T) {
	sc, _ := NewScanner()
	defer sc.Close()

	_, err := sc.ScanContent("", []byte("content"))
	if err == nil {
		t.Error("ScanContent should error on empty filename")
	}
}

func TestScanContent_EmptyContent(t *testing.T) {
	sc, _ := NewScanner()
	defer sc.Close()

	result, err := sc.ScanContent("empty.txt", []byte(""))
	if err != nil {
		t.Fatalf("ScanContent error: %v", err)
	}

	// Empty content may produce 0 findings or binary detection.
	_ = result
}

func TestScanContent_MultipleFindings(t *testing.T) {
	sc, _ := NewScanner()
	defer sc.Close()

	content := []byte(`line1: AKIAIOSFODNN7EXAMPLE
line2: ghp_1234567890abcdefghijklmnopqrstuvwxyz
line3: 123-45-6789
`)
	result, err := sc.ScanContent("multi.yaml", content)
	if err != nil {
		t.Fatalf("ScanContent error: %v", err)
	}

	if result.Stats.TotalFindings < 2 {
		t.Errorf("expected at least 2 findings, got %d", result.Stats.TotalFindings)
	}
}

// ---------------------------------------------------------------------
// ScanReader tests
// ---------------------------------------------------------------------

func TestScanReader_Basic(t *testing.T) {
	sc, _ := NewScanner()
	defer sc.Close()

	r := strings.NewReader("key = AKIAIOSFODNN7EXAMPLE\n")
	result, err := sc.ScanReader("config.yaml", r)
	if err != nil {
		t.Fatalf("ScanReader error: %v", err)
	}

	if result.Stats.TotalFindings == 0 {
		t.Error("expected at least 1 finding from reader")
	}
}

func TestScanReader_EmptyFilename(t *testing.T) {
	sc, _ := NewScanner()
	defer sc.Close()

	_, err := sc.ScanReader("", strings.NewReader("content"))
	if err == nil {
		t.Error("ScanReader should error on empty filename")
	}
}

// ---------------------------------------------------------------------
// ScanFiles tests
// ---------------------------------------------------------------------

func TestScanFiles_Basic(t *testing.T) {
	dir := t.TempDir()

	path1 := filepath.Join(dir, "file1.yaml")
	path2 := filepath.Join(dir, "file2.yaml")
	os.WriteFile(path1, []byte("key: AKIAIOSFODNN7EXAMPLE\n"), 0644)
	os.WriteFile(path2, []byte("safe: content\n"), 0644)

	sc, _ := NewScanner()
	defer sc.Close()

	result, err := sc.ScanFiles([]string{path1, path2})
	if err != nil {
		t.Fatalf("ScanFiles error: %v", err)
	}

	if result.Stats.FilesScanned != 2 {
		t.Errorf("expected 2 files scanned, got %d", result.Stats.FilesScanned)
	}
	if result.Stats.TotalFindings == 0 {
		t.Error("expected at least 1 finding from file1")
	}
}

func TestScanFiles_Empty(t *testing.T) {
	sc, _ := NewScanner()
	defer sc.Close()

	_, err := sc.ScanFiles(nil)
	if err == nil {
		t.Error("ScanFiles should error on empty list")
	}
}

func TestScanFiles_NonExistent(t *testing.T) {
	sc, _ := NewScanner()
	defer sc.Close()

	// Non-existent files should be skipped, not error.
	result, err := sc.ScanFiles([]string{"nonexistent1.yaml", "nonexistent2.yaml"})
	if err != nil {
		t.Fatalf("ScanFiles error: %v", err)
	}
	if result.Stats.FilesScanned != 0 {
		t.Errorf("expected 0 files scanned for non-existent, got %d", result.Stats.FilesScanned)
	}
}

// ---------------------------------------------------------------------
// Close tests
// ---------------------------------------------------------------------

func TestClose(t *testing.T) {
	sc, _ := NewScanner()
	if err := sc.Close(); err != nil {
		t.Errorf("Close error: %v", err)
	}
}

// ---------------------------------------------------------------------
// Helper tests
// ---------------------------------------------------------------------

func TestParseAPISeverity(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"critical", "critical"},
		{"high", "high"},
		{"medium", "medium"},
		{"low", "low"},
		{"", ""},
		{"unknown", ""},
	}

	for _, tt := range tests {
		got := parseAPISeverity(tt.input)
		if string(got) != tt.expect {
			t.Errorf("parseAPISeverity(%s) = %s, want %s", tt.input, got, tt.expect)
		}
	}
}
