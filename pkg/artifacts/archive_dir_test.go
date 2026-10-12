// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractTarGz_WithDirectories(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "with_dirs.tar.gz")

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)

	// Add a directory entry
	tw.WriteHeader(&tar.Header{
		Name:     "subdir/",
		Mode:     0755,
		Typeflag: tar.TypeDir,
	})

	// Add a file in that directory
	content := "nested content"
	tw.WriteHeader(&tar.Header{
		Name: "subdir/file.txt",
		Mode: 0644,
		Size: int64(len(content)),
	})
	tw.Write([]byte(content))

	// Add another file at root
	content2 := "root content"
	tw.WriteHeader(&tar.Header{
		Name: "root.txt",
		Mode: 0644,
		Size: int64(len(content2)),
	})
	tw.Write([]byte(content2))

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

	// Verify nested file
	data, err := os.ReadFile(filepath.Join(result.Dir, "subdir", "file.txt"))
	if err != nil {
		t.Fatalf("nested file not extracted: %v", err)
	}
	if string(data) != "nested content" {
		t.Errorf("nested content = %q, want 'nested content'", string(data))
	}

	// Verify root file
	data2, err := os.ReadFile(filepath.Join(result.Dir, "root.txt"))
	if err != nil {
		t.Fatalf("root file not extracted: %v", err)
	}
	if string(data2) != "root content" {
		t.Errorf("root content = %q, want 'root content'", string(data2))
	}

	// Verify we got 2 files (directory entry shouldn't count as a file)
	if len(result.Files) < 2 {
		t.Errorf("expected at least 2 files, got %d", len(result.Files))
	}
}

func TestExtractTarBz2_WithFiles(t *testing.T) {
	// Since Go stdlib doesn't have a bzip2 writer, we can't create
	// a valid .tar.bz2 file. But we can test that the function
	// properly attempts to decompress invalid data and returns an error.
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "test.tar.bz2")

	// Create some data that looks like it might be bzip2 but isn't valid tar
	// bzip2 files start with "BZh"
	os.WriteFile(tarPath, []byte("BZh9\x00\x00\x00\x00invalid"), 0644)

	_, err := ExtractArchive(tarPath)
	if err == nil {
		t.Error("expected error for invalid tar.bz2 content")
	}
}
