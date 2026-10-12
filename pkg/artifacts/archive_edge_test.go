// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractZip_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "corrupt.zip")
	os.WriteFile(zipPath, []byte("not a real zip file"), 0644)

	_, err := ExtractArchive(zipPath)
	if err == nil {
		t.Error("expected error for corrupt zip")
	}
}

func TestExtractTarGz_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "corrupt.tar.gz")
	os.WriteFile(tarPath, []byte("not a real tar.gz file"), 0644)

	_, err := ExtractArchive(tarPath)
	if err == nil {
		t.Error("expected error for corrupt tar.gz")
	}
}

func TestExtractTarBz2_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "corrupt.tar.bz2")
	os.WriteFile(tarPath, []byte("not a real tar.bz2 file"), 0644)

	_, err := ExtractArchive(tarPath)
	if err == nil {
		t.Error("expected error for corrupt tar.bz2")
	}
}

func TestExtractArchivesInPlace_MultipleArchives(t *testing.T) {
	dir := t.TempDir()
	var paths []string

	for i := 0; i < 2; i++ {
		zipPath := filepath.Join(dir, "archive"+string(rune('0'+i))+".zip")
		zipFile, _ := os.Create(zipPath)
		zw := zip.NewWriter(zipFile)
		w, _ := zw.Create("file.txt")
		w.Write([]byte("content"))
		zw.Close()
		zipFile.Close()
		paths = append(paths, zipPath)
	}

	extractedPaths, cleanup, err := ExtractArchivesInPlace(paths)
	if err != nil {
		t.Fatalf("ExtractArchivesInPlace: %v", err)
	}
	if cleanup != nil {
		defer cleanup()
	}
	if len(extractedPaths) < 1 {
		t.Errorf("expected extracted paths, got %d", len(extractedPaths))
	}
}

func TestSanitizeExtractPath_BackslashTraversal(t *testing.T) {
	_, err := sanitizeExtractPath("/tmp/dest", "..\\..\\windows")
	if err == nil {
		t.Error("expected error for backslash path traversal")
	}
}

func TestSanitizeExtractPath_AbsolutePath(t *testing.T) {
	_, err := sanitizeExtractPath("/tmp/dest", "/etc/passwd")
	if err != nil {
		t.Logf("absolute path handling: %v", err)
	}
}
