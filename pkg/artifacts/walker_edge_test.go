// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — File Walker Edge Case Tests
// =========================================================================
//
// Edge case tests for the artifacts walker covering:
//   - Large file skipping (exceeds max_file_size)
//   - Empty file skipping (0 bytes)
//   - Binary file detection (null bytes)
//   - Unicode content reading (emoji, CJK, RTL, combining chars)
//   - Deep nested directories (10 levels)
//   - Many files in one directory (1000 files)
//   - UTF-8 BOM stripping
//   - CRLF line ending handling
//   - Permission denied handling (skipped if root)
//   - Extension filtering
//   - Ignore pattern exclusion
//   - No supported files in directory
//
// All tests use t.TempDir() for automatic cleanup and only stdlib.
//
// =========================================================================

package artifacts

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------
// Large file
// ---------------------------------------------------------------------

// TestWalk_LargeFile_Skipped verifies that a file exceeding
// MaxFileSize is skipped with a reason containing "too large".
func TestWalk_LargeFile_Skipped(t *testing.T) {
	dir := t.TempDir()

	// Create a ~400 byte file, set max to 100 bytes.
	content := strings.Repeat("This is a test line with some content.\n", 10)
	writeFile(t, filepath.Join(dir, "big.txt"), content)

	result, err := Walk(WalkOptions{
		Root:        dir,
		MaxFileSize: 100,
	})
	if err != nil {
		t.Fatalf("Walk() error: %v", err)
	}

	if len(result.Artifacts) != 0 {
		t.Errorf("expected 0 artifacts, got %d", len(result.Artifacts))
	}

	skipped := findSkipped(result.Skipped, "big.txt")
	if skipped == nil {
		t.Fatal("expected big.txt to be in skipped list")
	}
	if !strings.Contains(skipped.Skipped, "too large") {
		t.Errorf("skip reason = %q, want it to contain 'too large'", skipped.Skipped)
	}
}

// ---------------------------------------------------------------------
// Empty file
// ---------------------------------------------------------------------

// TestWalk_EmptyFile_Skipped verifies that an empty (0-byte) file is
// skipped. Empty files trigger a read error in isBinary() and are
// skipped with a "binary check error" reason.
func TestWalk_EmptyFile_Skipped(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "empty.txt"), "")

	result, err := Walk(WalkOptions{Root: dir})
	if err != nil {
		t.Fatalf("Walk() error: %v", err)
	}

	if containsArtifact(result.Artifacts, "empty.txt") {
		t.Error("empty.txt should not be in artifacts")
	}

	skipped := findSkipped(result.Skipped, "empty.txt")
	if skipped == nil {
		t.Fatal("expected empty.txt to be in skipped list")
	}
	// Empty files are caught by isBinary() returning an error on EOF.
	if !strings.Contains(skipped.Skipped, "binary check error") {
		t.Errorf("skip reason = %q, want 'binary check error'", skipped.Skipped)
	}
}

// ---------------------------------------------------------------------
// Binary file
// ---------------------------------------------------------------------

// TestWalk_BinaryFile_Skipped verifies that a file with null bytes is
// detected as binary and skipped with the Binary flag set.
func TestWalk_BinaryFile_Skipped(t *testing.T) {
	dir := t.TempDir()

	// .txt is a supported extension, but null bytes make it binary.
	binaryContent := []byte("text\x00\x00more\x00binary\x00data")
	writeFileBytes(t, filepath.Join(dir, "blob.txt"), binaryContent)

	// Also create a valid text file for comparison.
	writeFile(t, filepath.Join(dir, "text.txt"), "normal text content\n")

	result, err := Walk(WalkOptions{Root: dir})
	if err != nil {
		t.Fatalf("Walk() error: %v", err)
	}

	if !containsArtifact(result.Artifacts, "text.txt") {
		t.Error("text.txt should be in artifacts")
	}
	if containsArtifact(result.Artifacts, "blob.txt") {
		t.Error("blob.txt should not be in artifacts")
	}

	skipped := findSkipped(result.Skipped, "blob.txt")
	if skipped == nil {
		t.Fatal("expected blob.txt to be in skipped list")
	}
	if !skipped.Binary {
		t.Error("expected Binary flag to be true")
	}
	if skipped.Skipped != "binary file" {
		t.Errorf("skip reason = %q, want 'binary file'", skipped.Skipped)
	}
}

// ---------------------------------------------------------------------
// Unicode content
// ---------------------------------------------------------------------

// TestWalk_UnicodeContent verifies that files containing emoji, CJK,
// RTL, and combining characters are read correctly and not flagged
// as binary.
func TestWalk_UnicodeContent(t *testing.T) {
	dir := t.TempDir()

	// Include: emoji (🎉), CJK (你好世界), RTL (مرحبا), combining (café)
	content := "Emoji: 🎉 party time\n" +
		"CJK: 你好世界\n" +
		"RTL: مرحبا بالعالم\n" +
		"Combining: café résumé naïve\n"

	writeFile(t, filepath.Join(dir, "unicode.txt"), content)

	result, err := Walk(WalkOptions{Root: dir})
	if err != nil {
		t.Fatalf("Walk() error: %v", err)
	}

	if len(result.Artifacts) != 1 {
		t.Fatalf("expected 1 artifact, got %d", len(result.Artifacts))
	}

	art := result.Artifacts[0]
	if art.Path != "unicode.txt" {
		t.Errorf("artifact path = %q, want 'unicode.txt'", art.Path)
	}
	if art.Content != content {
		t.Errorf("content mismatch:\n  expected: %q\n  got:      %q", content, art.Content)
	}
	if art.Binary {
		t.Error("Unicode file should not be flagged as binary")
	}
}

// ---------------------------------------------------------------------
// Deep nested directories
// ---------------------------------------------------------------------

// TestWalk_DeepNestedDirectories verifies that files 10 levels deep
// in nested directories are found by the walker.
func TestWalk_DeepNestedDirectories(t *testing.T) {
	dir := t.TempDir()

	// Create 10 levels of nesting: l0/l1/l2/.../l9/deep.txt
	deepDir := filepath.Join(dir, "l0", "l1", "l2", "l3", "l4", "l5", "l6", "l7", "l8", "l9")
	if err := os.MkdirAll(deepDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error: %v", err)
	}
	filePath := filepath.Join(deepDir, "deep.txt")
	if err := os.WriteFile(filePath, []byte("deep content\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	result, err := Walk(WalkOptions{Root: dir})
	if err != nil {
		t.Fatalf("Walk() error: %v", err)
	}

	if len(result.Artifacts) != 1 {
		t.Fatalf("expected 1 artifact, got %d", len(result.Artifacts))
	}

	art := result.Artifacts[0]
	if !strings.HasSuffix(art.Path, "deep.txt") {
		t.Errorf("artifact path = %q, want suffix 'deep.txt'", art.Path)
	}
	if !strings.Contains(art.Path, "l0/l1/l2/l3/l4/l5/l6/l7/l8/l9/deep.txt") {
		t.Errorf("artifact path = %q, want 10-level nesting", art.Path)
	}
}

// ---------------------------------------------------------------------
// Many files
// ---------------------------------------------------------------------

// TestWalk_ManyFiles verifies that 1000 small files in a single
// directory are all found by the walker.
func TestWalk_ManyFiles(t *testing.T) {
	dir := t.TempDir()

	for i := 0; i < 1000; i++ {
		fileName := "file_" + strconv.Itoa(i) + ".txt"
		filePath := filepath.Join(dir, fileName)
		if err := os.WriteFile(filePath, []byte("content\n"), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error: %v", fileName, err)
		}
	}

	result, err := Walk(WalkOptions{Root: dir})
	if err != nil {
		t.Fatalf("Walk() error: %v", err)
	}

	if len(result.Artifacts) != 1000 {
		t.Errorf("expected 1000 artifacts, got %d", len(result.Artifacts))
	}
}

// ---------------------------------------------------------------------
// BOM handling
// ---------------------------------------------------------------------

// TestWalk_FileWithBOM verifies that a UTF-8 BOM (EF BB BF) at the
// start of a file is stripped from the content.
func TestWalk_FileWithBOM(t *testing.T) {
	dir := t.TempDir()

	// Create a file with UTF-8 BOM prefix.
	bomContent := "\xEF\xBB\xBFHello world with BOM\n"
	filePath := filepath.Join(dir, "bom.txt")
	if err := os.WriteFile(filePath, []byte(bomContent), 0o644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	result, err := Walk(WalkOptions{Root: dir})
	if err != nil {
		t.Fatalf("Walk() error: %v", err)
	}

	if len(result.Artifacts) != 1 {
		t.Fatalf("expected 1 artifact, got %d", len(result.Artifacts))
	}

	art := result.Artifacts[0]
	if strings.HasPrefix(art.Content, "\xEF\xBB\xBF") {
		t.Error("BOM should be stripped from content")
	}
	expected := "Hello world with BOM\n"
	if art.Content != expected {
		t.Errorf("content = %q, want %q", art.Content, expected)
	}
}

// ---------------------------------------------------------------------
// CRLF handling
// ---------------------------------------------------------------------

// TestWalk_FileWithCRLF verifies that files with CRLF (\r\n) line
// endings are read correctly with accurate line counts.
func TestWalk_FileWithCRLF(t *testing.T) {
	dir := t.TempDir()

	content := "line1\r\nline2\r\nline3\r\n"
	writeFile(t, filepath.Join(dir, "crlf.txt"), content)

	result, err := Walk(WalkOptions{Root: dir})
	if err != nil {
		t.Fatalf("Walk() error: %v", err)
	}

	if len(result.Artifacts) != 1 {
		t.Fatalf("expected 1 artifact, got %d", len(result.Artifacts))
	}

	art := result.Artifacts[0]
	if art.Content != content {
		t.Errorf("content = %q, want %q", art.Content, content)
	}
	// 3 \n characters, ends with \n → 3 lines.
	if art.Lines != 3 {
		t.Errorf("lines = %d, want 3", art.Lines)
	}
}

// ---------------------------------------------------------------------
// Permission denied
// ---------------------------------------------------------------------

// TestWalk_PermissionDenied verifies that a file with no read
// permission is skipped with a reason. The test is skipped when
// running as root since root bypasses file permissions.
func TestWalk_PermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission test when running as root")
	}

	dir := t.TempDir()
	filePath := filepath.Join(dir, "noperm.txt")
	writeFile(t, filePath, "some content that cannot be read\n")

	// Remove all permissions.
	if err := os.Chmod(filePath, 0o000); err != nil {
		t.Fatalf("chmod() error: %v", err)
	}
	// Restore permissions so TempDir cleanup can delete the file.
	defer os.Chmod(filePath, 0o644)

	result, err := Walk(WalkOptions{Root: dir})
	if err != nil {
		t.Fatalf("Walk() error: %v", err)
	}

	if containsArtifact(result.Artifacts, "noperm.txt") {
		t.Error("noperm.txt should not be in artifacts")
	}

	skipped := findSkipped(result.Skipped, "noperm.txt")
	if skipped == nil {
		t.Fatal("expected noperm.txt to be in skipped list")
	}
	if skipped.Skipped == "" {
		t.Error("expected non-empty skip reason for permission-denied file")
	}
}

// ---------------------------------------------------------------------
// Extension filter
// ---------------------------------------------------------------------

// TestWalk_ExtensionsFilter verifies that only files matching the
// extension filter are included in the artifacts.
func TestWalk_ExtensionsFilter(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "doc.txt"), "text content\n")
	writeFile(t, filepath.Join(dir, "data.json"), `{"key": "value"}`+"\n")
	writeFile(t, filepath.Join(dir, "readme.md"), "# README\n")

	result, err := Walk(WalkOptions{
		Root:       dir,
		Extensions: []string{".txt"},
	})
	if err != nil {
		t.Fatalf("Walk() error: %v", err)
	}

	if len(result.Artifacts) != 1 {
		t.Fatalf("expected 1 artifact, got %d", len(result.Artifacts))
	}
	if result.Artifacts[0].Path != "doc.txt" {
		t.Errorf("artifact path = %q, want 'doc.txt'", result.Artifacts[0].Path)
	}

	// Verify the other files are not in artifacts.
	if containsArtifact(result.Artifacts, "data.json") {
		t.Error("data.json should not be in artifacts when filtering for .txt")
	}
	if containsArtifact(result.Artifacts, "readme.md") {
		t.Error("readme.md should not be in artifacts when filtering for .txt")
	}
}

// ---------------------------------------------------------------------
// Ignore patterns
// ---------------------------------------------------------------------

// TestWalk_IgnorePatterns verifies that files matching user-specified
// ignore patterns are excluded from artifacts.
func TestWalk_IgnorePatterns(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "keep.txt"), "keep this file\n")
	writeFile(t, filepath.Join(dir, "secret.txt"), "secret content\n")
	writeFile(t, filepath.Join(dir, "normal.md"), "normal content\n")

	result, err := Walk(WalkOptions{
		Root:        dir,
		IgnorePaths: []string{"secret*"},
	})
	if err != nil {
		t.Fatalf("Walk() error: %v", err)
	}

	// secret.txt should be excluded.
	if containsArtifact(result.Artifacts, "secret.txt") {
		t.Error("secret.txt should be ignored")
	}

	// keep.txt and normal.md should be present.
	if !containsArtifact(result.Artifacts, "keep.txt") {
		t.Error("keep.txt should be in artifacts")
	}
	if !containsArtifact(result.Artifacts, "normal.md") {
		t.Error("normal.md should be in artifacts")
	}
}

// ---------------------------------------------------------------------
// No supported files
// ---------------------------------------------------------------------

// TestWalk_NoSupportedFiles verifies that a directory containing only
// unsupported file types (.exe, .bin) returns an empty artifacts list.
func TestWalk_NoSupportedFiles(t *testing.T) {
	dir := t.TempDir()

	// Create only unsupported file types (also in default ignore list).
	if err := os.WriteFile(filepath.Join(dir, "app.exe"), []byte("binary\x00content"), 0o644); err != nil {
		t.Fatalf("WriteFile(app.exe) error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data.bin"), []byte("binary\x00data"), 0o644); err != nil {
		t.Fatalf("WriteFile(data.bin) error: %v", err)
	}

	result, err := Walk(WalkOptions{Root: dir})
	if err != nil {
		t.Fatalf("Walk() error: %v", err)
	}

	if len(result.Artifacts) != 0 {
		t.Errorf("expected 0 artifacts, got %d", len(result.Artifacts))
		for _, a := range result.Artifacts {
			t.Errorf("  unexpected artifact: %s", a.Path)
		}
	}
}
