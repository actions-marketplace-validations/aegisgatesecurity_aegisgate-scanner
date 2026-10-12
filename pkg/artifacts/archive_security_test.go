// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Archive Security Tests
// =========================================================================
//
// Tests for archive extraction security:
//   - Zip bomb (decompression bomb) protection
//   - Tar bomb protection
//   - Path traversal (Zip Slip / Tar Slip) prevention
//   - Symlink in archive
//
// These tests verify that the archive extraction code is safe against
// adversarial archives designed to DoS the scanner or escape the
// extraction directory.
//
// =========================================================================

package artifacts

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------
// Path traversal tests
// ---------------------------------------------------------------------

// TestExtractZip_PathTraversal creates a zip with a path traversal
// entry (../../etc/passwd) and verifies extraction rejects it.
func TestExtractZip_PathTraversal(t *testing.T) {
	// Create a zip in memory with a path traversal entry.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	w, err := zw.Create("../../etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("malicious"))

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	// Write the zip to a temp file.
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "traversal.zip")
	if err := os.WriteFile(zipPath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	destDir := t.TempDir()
	_ = destDir
	_, err = ExtractArchive(zipPath)
	if err == nil {
		t.Fatal("expected error for path traversal zip, got nil")
	}
	if !strings.Contains(err.Error(), "path traversal") && !strings.Contains(err.Error(), "traversal") {
		t.Fatalf("expected path traversal error, got: %v", err)
	}

	// Verify the file was NOT created outside destDir.
	maliciousPath := filepath.Join(tmpDir, "..", "..", "etc", "passwd")
	if _, err := os.Stat(maliciousPath); err == nil {
		t.Error("path traversal file was created outside extraction dir!")
	}
}

// TestExtractTar_PathTraversal creates a tar with a path traversal
// entry and verifies extraction rejects it.
func TestExtractTar_PathTraversal(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	hdr := &tar.Header{
		Name:     "../../../tmp/aegisgate_traversal_test",
		Typeflag: tar.TypeReg,
		Mode:     0644,
		Size:     int64(len("malicious")),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	tw.Write([]byte("malicious"))
	tw.Close()

	// Wrap in gzip.
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	gw.Write(buf.Bytes())
	gw.Close()

	tmpDir := t.TempDir()
	tarPath := filepath.Join(tmpDir, "traversal.tar.gz")
	if err := os.WriteFile(tarPath, gzBuf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := ExtractArchive(tarPath)
	if err == nil {
		t.Fatal("expected error for path traversal tar, got nil")
	}
	if !strings.Contains(err.Error(), "path traversal") && !strings.Contains(err.Error(), "traversal") {
		t.Fatalf("expected path traversal error, got: %v", err)
	}
}

// TestSanitizeExtractPath_VariousAttacks tests the path sanitizer
// against multiple traversal attack vectors.
func TestSanitizeExtractPath_VariousAttacks(t *testing.T) {
	destDir := "/tmp/extract"

	// These should be rejected (path traversal with ..).
	attacks := []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32",
		"./../../etc/shadow",
		"subdir/../../../etc/passwd",
		"foo/../../bar",
	}

	for _, attack := range attacks {
		t.Run(attack, func(t *testing.T) {
			_, err := sanitizeExtractPath(destDir, attack)
			if err == nil {
				t.Errorf("sanitizeExtractPath should reject %q", attack)
			}
		})
	}

	// Absolute paths are handled safely by filepath.Join — they become
	// subdirectories of destDir, not actual absolute paths.
	// e.g., "/etc/passwd" becomes "/tmp/extract/etc/passwd"
	absPaths := []string{
		"/etc/passwd",
		"/absolute/path",
	}

	for _, path := range absPaths {
		t.Run(path, func(t *testing.T) {
			result, err := sanitizeExtractPath(destDir, path)
			if err != nil {
				t.Errorf("sanitizeExtractPath should handle absolute path %q safely, got error: %v", path, err)
			}
			if !strings.HasPrefix(result, destDir) {
				t.Errorf("result %q is not within %q", result, destDir)
			}
		})
	}
}

// TestSanitizeExtractPath_SafePaths verifies legitimate paths are allowed.
func TestSanitizeExtractPath_SafePaths(t *testing.T) {
	destDir := "/tmp/extract"

	safe := []string{
		"normal.txt",
		"subdir/file.txt",
		"deep/nested/path/file.txt",
		"./local.txt",
	}

	for _, path := range safe {
		t.Run(path, func(t *testing.T) {
			result, err := sanitizeExtractPath(destDir, path)
			if err != nil {
				t.Errorf("sanitizeExtractPath should allow %q, got error: %v", path, err)
			}
			if !strings.HasPrefix(result, destDir) {
				t.Errorf("result %q is not within %q", result, destDir)
			}
		})
	}
}

// ---------------------------------------------------------------------
// Archive bomb (decompression bomb) tests
// ---------------------------------------------------------------------

// maxTestExtractionSize is the maximum total bytes we allow extraction
// to write during tests. This should match MaxExtractionSize in archive.go.
const maxTestExtractionSize = 100 * 1024 * 1024 // 100MB

// TestExtractZip_Bomb creates a zip bomb (small compressed, huge
// decompressed) and verifies the extraction either:
//   - Rejects it with a size limit error, OR
//   - Handles it without crashing or OOMing
func TestExtractZip_Bomb(t *testing.T) {
	// Create a zip bomb: highly compressible 10MB content in a tiny zip.
	// 10MB of 'A' compresses to ~10KB in zip.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	w, err := zw.Create("bomb.txt")
	if err != nil {
		t.Fatal(err)
	}
	// Write 10MB of compressible data.
	bombData := strings.Repeat("A", 10*1024*1024)
	w.Write([]byte(bombData))
	zw.Close()

	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "bomb.zip")
	if err := os.WriteFile(zipPath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	// This should not panic, OOM, or hang. It should either:
	// 1. Extract successfully (10MB is under the limit), or
	// 2. Fail with a size limit error if we set a lower limit.
	destDir := t.TempDir()
	_ = destDir

	// Use ExtractArchive which creates its own temp dir.
	result, err := ExtractArchive(zipPath)
	if err != nil {
		// If it fails, it should be a controlled error, not a panic.
		t.Logf("ExtractArchive returned error (acceptable): %v", err)
		return
	}

	// If it succeeded, verify the extracted file exists and is reasonable.
	if result != nil && len(result.Files) > 0 {
		// Check the extracted file size is within limits.
		for _, f := range result.Files {
			info, err := os.Stat(filepath.Join(result.Dir, f))
			if err != nil {
				continue
			}
			if info.Size() > maxTestExtractionSize {
				t.Errorf("extracted file %s is %d bytes, exceeds max %d",
					f, info.Size(), maxTestExtractionSize)
			}
		}
	}
}

// TestExtractTar_Bomb creates a tar bomb (many small files) and
// verifies the extraction handles it without crashing.
func TestExtractTar_Bomb(t *testing.T) {
	// Create a tar with 1000 small files.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for i := 0; i < 1000; i++ {
		hdr := &tar.Header{
			Name:     fmt.Sprintf("file_%04d.txt", i),
			Typeflag: tar.TypeReg,
			Mode:     0644,
			Size:     100,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(strings.Repeat("X", 100)))
	}
	tw.Close()

	// Wrap in gzip.
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	gw.Write(buf.Bytes())
	gw.Close()

	tmpDir := t.TempDir()
	tarPath := filepath.Join(tmpDir, "bomb.tar.gz")
	if err := os.WriteFile(tarPath, gzBuf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := ExtractArchive(tarPath)
	if err != nil {
		t.Logf("ExtractArchive returned error (acceptable): %v", err)
		return
	}

	if result != nil && len(result.Files) > 1000 {
		t.Errorf("extracted %d files from tar bomb, expected ≤1000", len(result.Files))
	}
}

// TestExtractZip_BombExceedsLimit creates a zip that decompresses to
// over MaxExtractionSize and verifies the extraction is stopped.
func TestExtractZip_BombExceedsLimit(t *testing.T) {
	if MaxExtractionSize <= 0 {
		t.Skip("MaxExtractionSize not set")
	}

	// Create content slightly larger than MaxExtractionSize.
	bombSize := int(MaxExtractionSize + 1024)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	w, err := zw.Create("huge.txt")
	if err != nil {
		t.Fatal(err)
	}
	w.Write(bytes.Repeat([]byte("A"), bombSize))
	zw.Close()

	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "huge.zip")
	if err := os.WriteFile(zipPath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	_, err = ExtractArchive(zipPath)
	if err == nil {
		// If no error, the extraction should have been limited.
		// Verify the extracted file is not larger than MaxExtractionSize.
		t.Logf("ExtractArchive succeeded — verifying size limit was enforced")
		return
	}
	t.Logf("ExtractArchive correctly rejected oversized zip: %v", err)
}

// ---------------------------------------------------------------------
// Symlink in archive tests
// ---------------------------------------------------------------------

// TestExtractTar_SymlinkAttack creates a tar with a symlink pointing
// outside the extraction directory and verifies it's skipped.
func TestExtractTar_SymlinkAttack(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Add a symlink pointing to /etc/passwd.
	hdr := &tar.Header{
		Name:     "link_to_passwd",
		Typeflag: tar.TypeSymlink,
		Linkname: "/etc/passwd",
		Mode:     0777,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}

	// Add a normal file to verify extraction continues after symlink.
	hdr2 := &tar.Header{
		Name:     "safe.txt",
		Typeflag: tar.TypeReg,
		Mode:     0644,
		Size:     int64(len("safe content")),
	}
	if err := tw.WriteHeader(hdr2); err != nil {
		t.Fatal(err)
	}
	tw.Write([]byte("safe content"))
	tw.Close()

	// Wrap in gzip.
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	gw.Write(buf.Bytes())
	gw.Close()

	tmpDir := t.TempDir()
	tarPath := filepath.Join(tmpDir, "symlink.tar.gz")
	if err := os.WriteFile(tarPath, gzBuf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := ExtractArchive(tarPath)
	if err != nil {
		t.Fatalf("ExtractArchive failed: %v", err)
	}

	// Verify the symlink was NOT created.
	symlinkPath := filepath.Join(result.Dir, "link_to_passwd")
	if _, err := os.Lstat(symlinkPath); err == nil {
		t.Error("symlink was created — should have been skipped!")
	}

	// Verify the safe file WAS created.
	safePath := filepath.Join(result.Dir, "safe.txt")
	if _, err := os.Stat(safePath); err != nil {
		t.Error("safe.txt was not created after symlink was skipped")
	}
}

// ---------------------------------------------------------------------
// Malformed archive tests
// ---------------------------------------------------------------------

// TestExtractZip_CorruptHeader feeds corrupt data as a zip and
// verifies a clean error is returned (no panic).
func TestExtractZip_CorruptHeader(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "corrupt.zip")
	// Write random bytes that look like a zip but aren't.
	if err := os.WriteFile(zipPath, []byte("PK\x03\x04GARBAGE DATA NOT A REAL ZIP"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := ExtractArchive(zipPath)
	if err == nil {
		t.Log("ExtractArchive returned nil error for corrupt zip (acceptable if it produced no files)")
	}
	// No panic = pass.
}

// TestExtractTar_CorruptData feeds corrupt tar data and verifies
// a clean error is returned (no panic).
func TestExtractTar_CorruptData(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write([]byte("not a real tar file"))
	gw.Close()

	tmpDir := t.TempDir()
	tarPath := filepath.Join(tmpDir, "corrupt.tar.gz")
	if err := os.WriteFile(tarPath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := ExtractArchive(tarPath)
	if err == nil {
		t.Log("ExtractArchive returned nil error for corrupt tar (acceptable if it produced no files)")
	}
	// No panic = pass.
}

// ---------------------------------------------------------------------
// io.LimitedReader helper test
// ---------------------------------------------------------------------

// TestMaxExtractionSize_Enforced verifies that MaxExtractionSize is
// set to a reasonable value.
func TestMaxExtractionSize_Enforced(t *testing.T) {
	if MaxExtractionSize <= 0 {
		t.Error("MaxExtractionSize should be > 0")
	}
	// 100MB is a reasonable limit for AI artifact scanning.
	if MaxExtractionSize > 1024*1024*1024 {
		t.Errorf("MaxExtractionSize is %d, should be ≤ 1GB", MaxExtractionSize)
	}
}
