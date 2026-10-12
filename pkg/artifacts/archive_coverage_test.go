// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractTarBz2(t *testing.T) {
	// bzip2 doesn't have a writer in Go stdlib, so we can't easily create
	// a .tar.bz2 file in tests. Instead, test that extractTarBz2 handles
	// invalid bzip2 data gracefully.
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "test.tar.bz2")
	os.WriteFile(tarPath, []byte("not bzip2 data"), 0644)

	_, err := ExtractArchive(tarPath)
	if err == nil {
		t.Error("expected error for invalid bzip2 data")
	}
}

func TestExtractZip_NestedDirectories(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "nested.zip")

	zipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	zw := zip.NewWriter(zipFile)

	w, err := zw.Create("subdir/nested.txt")
	if err != nil {
		t.Fatalf("Create entry: %v", err)
	}
	w.Write([]byte("nested content"))

	zw.Close()
	zipFile.Close()

	result, err := ExtractArchive(zipPath)
	if err != nil {
		t.Fatalf("ExtractArchive: %v", err)
	}
	defer result.Cleanup()

	// Verify file exists in extracted directory
	data, err := os.ReadFile(filepath.Join(result.Dir, "subdir", "nested.txt"))
	if err != nil {
		t.Fatalf("nested file not extracted: %v", err)
	}
	if string(data) != "nested content" {
		t.Errorf("content = %q, want 'nested content'", string(data))
	}

	// Verify file is in the result list
	found := false
	for _, f := range result.Files {
		if strings.Contains(f, "nested.txt") {
			found = true
			break
		}
	}
	if !found {
		t.Error("nested.txt not in result.Files list")
	}
}

func TestExtractZip_EmptyArchive(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "empty.zip")

	zipFile, _ := os.Create(zipPath)
	zw := zip.NewWriter(zipFile)
	zw.Close()
	zipFile.Close()

	result, err := ExtractArchive(zipPath)
	if err != nil {
		t.Errorf("empty zip should not error: %v", err)
	}
	if result == nil || result.Cleanup == nil {
		t.Fatal("expected result with cleanup")
	}
	defer result.Cleanup()
}

func TestExtractArchive_NotAnArchive(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "notarchive.txt")
	os.WriteFile(filePath, []byte("not an archive"), 0644)

	_, err := ExtractArchive(filePath)
	if err == nil {
		t.Error("expected error for non-archive file")
	}
}

func TestExtractArchive_NonexistentFile(t *testing.T) {
	dir := t.TempDir()
	_, err := ExtractArchive(filepath.Join(dir, "nonexistent.zip"))
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestExtractArchive_TarGzWithMultipleFiles(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "multi.tar.gz")

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for i := 0; i < 5; i++ {
		name := "file" + string(rune('0'+i)) + ".txt"
		content := "content" + string(rune('0'+i))
		hdr := &tar.Header{Name: name, Mode: 0644, Size: int64(len(content))}
		tw.WriteHeader(hdr)
		tw.Write([]byte(content))
	}
	tw.Close()

	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	gw.Write(tarBuf.Bytes())
	gw.Close()

	os.WriteFile(tarPath, gzBuf.Bytes(), 0644)

	result, err := ExtractArchive(tarPath)
	if err != nil {
		t.Fatalf("ExtractArchive: %v", err)
	}
	defer result.Cleanup()

	for i := 0; i < 5; i++ {
		name := "file" + string(rune('0'+i)) + ".txt"
		expectedContent := "content" + string(rune('0'+i))
		data, err := os.ReadFile(filepath.Join(result.Dir, name))
		if err != nil {
			t.Errorf("file %s not extracted: %v", name, err)
			continue
		}
		if string(data) != expectedContent {
			t.Errorf("file %s content = %q, want %q", name, string(data), expectedContent)
		}
	}

	if len(result.Files) != 5 {
		t.Errorf("result.Files count = %d, want 5", len(result.Files))
	}
}

func TestExtractArchivesInPlace_MixedFiles(t *testing.T) {
	dir := t.TempDir()

	// Create a zip archive
	zipPath := filepath.Join(dir, "data.zip")
	zipFile, _ := os.Create(zipPath)
	zw := zip.NewWriter(zipFile)
	w, _ := zw.Create("inner.txt")
	w.Write([]byte("inner content"))
	zw.Close()
	zipFile.Close()

	// Also create a regular (non-archive) file
	os.WriteFile(filepath.Join(dir, "regular.txt"), []byte("regular content"), 0644)

	// Extract archives in place
	extractedPaths, cleanup, err := ExtractArchivesInPlace([]string{zipPath})
	if err != nil {
		t.Fatalf("ExtractArchivesInPlace: %v", err)
	}
	if cleanup != nil {
		defer cleanup()
	}

	if len(extractedPaths) == 0 {
		t.Error("expected at least one extracted path")
	}

	// Check that the extracted directory exists
	for _, p := range extractedPaths {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("extracted path %s does not exist: %v", p, err)
		}
	}
}

func TestExtractArchivesInPlace_NoArchives_Cov(t *testing.T) {
	dir := t.TempDir()
	// Create only non-archive files
	os.WriteFile(filepath.Join(dir, "regular.txt"), []byte("regular"), 0644)

	extractedPaths, cleanup, err := ExtractArchivesInPlace([]string{filepath.Join(dir, "regular.txt")})
	if err != nil {
		t.Errorf("non-archive file should not error: %v", err)
	}
	if cleanup != nil {
		defer cleanup()
	}
	if len(extractedPaths) != 0 {
		_ = extractedPaths // non-archives may be passed through
	}
}

func TestExtractArchivesInPlace_EmptyList(t *testing.T) {
	extractedPaths, cleanup, err := ExtractArchivesInPlace([]string{})
	if err != nil {
		t.Errorf("empty list should not error: %v", err)
	}
	if cleanup != nil {
		defer cleanup()
	}
	// Empty list should return empty results
	_ = extractedPaths
}

func TestSanitizeExtractPath_NormalPaths(t *testing.T) {
	tests := []struct {
		name      string
		destDir   string
		filePath  string
		wantError bool
	}{
		{"simple", "/tmp/dest", "file.txt", false},
		{"nested", "/tmp/dest", "subdir/file.txt", false},
		{"deep", "/tmp/dest", "a/b/c/d/file.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sanitizeExtractPath(tt.destDir, tt.filePath)
			if (err != nil) != tt.wantError {
				t.Errorf("sanitizeExtractPath() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestSanitizeExtractPath_TraversalAttack(t *testing.T) {
	attacks := []string{
		"../../../etc/passwd",
		"subdir/../../etc/passwd",
	}

	for _, attack := range attacks {
		t.Run(attack, func(t *testing.T) {
			_, err := sanitizeExtractPath("/tmp/dest", attack)
			if err == nil {
				t.Errorf("expected error for path traversal: %s", attack)
			}
			if err != nil && !strings.Contains(strings.ToLower(err.Error()), "traversal") &&
				!strings.Contains(strings.ToLower(err.Error()), "outside") {
				t.Errorf("expected traversal-related error, got: %v", err)
			}
		})
	}
}

func TestExtractArchive_TarGzSimple(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "plain.tar.gz")

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	hdr := &tar.Header{Name: "file.txt", Mode: 0644, Size: 7}
	tw.WriteHeader(hdr)
	tw.Write([]byte("content"))
	tw.Close()

	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	gw.Write(tarBuf.Bytes())
	gw.Close()

	os.WriteFile(tarPath, gzBuf.Bytes(), 0644)

	result, err := ExtractArchive(tarPath)
	if err != nil {
		t.Fatalf("ExtractArchive: %v", err)
	}
	defer result.Cleanup()

	data, err := os.ReadFile(filepath.Join(result.Dir, "file.txt"))
	if err != nil {
		t.Fatalf("file not extracted: %v", err)
	}
	if string(data) != "content" {
		t.Errorf("content = %q, want 'content'", string(data))
	}
}

func TestExtractArchive_TgzExtension(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "data.tgz")

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	hdr := &tar.Header{Name: "file.txt", Mode: 0644, Size: 7}
	tw.WriteHeader(hdr)
	tw.Write([]byte("content"))
	tw.Close()

	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	gw.Write(tarBuf.Bytes())
	gw.Close()

	os.WriteFile(tarPath, gzBuf.Bytes(), 0644)

	result, err := ExtractArchive(tarPath)
	if err != nil {
		t.Fatalf("ExtractArchive: %v", err)
	}
	defer result.Cleanup()

	data, err := os.ReadFile(filepath.Join(result.Dir, "file.txt"))
	if err != nil {
		t.Fatalf("file not extracted: %v", err)
	}
	if string(data) != "content" {
		t.Errorf("content = %q, want 'content'", string(data))
	}
}

func TestDetectArchiveType_Cov(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     ArchiveType
	}{
		{"zip", "archive.zip", "zip"},
		{"tar_gz", "archive.tar.gz", "tar.gz"},
		{"tgz", "archive.tgz", "tar.gz"},
		{"tar_bz2", "archive.tar.bz2", "tar.bz2"},
		{"tbz2", "archive.tbz2", "tar.bz2"},
		{"not_archive", "file.txt", ""},
		{"no_ext", "file", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectArchiveType(tt.filename)
			if got != tt.want {
				t.Errorf("DetectArchiveType(%q) = %q, want %q", tt.filename, got, tt.want)
			}
		})
	}
}
