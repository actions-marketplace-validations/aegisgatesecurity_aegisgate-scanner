// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Walker coverage: RespectGitIgnore + symlink sub-walk skipped files
// ---------------------------------------------------------------------------

// TestWalk_GitIgnoreRespect_File covers the gitignore file-matching path
// in walkInternal (line 522): when RespectGitIgnore is true and a file
// matches a .gitignore pattern, it should be silently skipped.
func TestWalk_GitIgnoreRespect_File(t *testing.T) {
	dir := t.TempDir()
	// Create a .gitignore that ignores *.secret
	writeFile(t, filepath.Join(dir, ".gitignore"), "*.secret\n")
	// Create a matching file and a non-matching file
	writeFile(t, filepath.Join(dir, "data.secret"), "secret\n")
	writeFile(t, filepath.Join(dir, "doc.md"), "content\n")

	result, err := Walk(WalkOptions{
		Root:             dir,
		RespectGitIgnore: true,
	})
	if err != nil {
		t.Fatalf("Walk() error: %v", err)
	}
	// doc.md should be found
	if !containsArtifact(result.Artifacts, "doc.md") {
		t.Errorf("doc.md should be in artifacts")
	}
	// data.secret should NOT be found
	for _, a := range result.Artifacts {
		if a.Path == "data.secret" {
			t.Errorf("data.secret should be ignored by .gitignore")
		}
	}
}

// TestWalk_GitIgnoreRespect_Dir covers the gitignore directory-matching
// path in walkInternal (lines 517-521): when RespectGitIgnore is true and
// a directory matches a .gitignore pattern, filepath.SkipDir should be
// returned to skip the entire directory.
func TestWalk_GitIgnoreRespect_Dir(t *testing.T) {
	dir := t.TempDir()
	// Create a .gitignore that ignores the "excluded" directory
	writeFile(t, filepath.Join(dir, ".gitignore"), "excluded/\n")
	// Create the excluded directory with a file inside
	excludedDir := filepath.Join(dir, "excluded")
	writeFile(t, filepath.Join(excludedDir, "secret.md"), "secret\n")
	// Create a non-excluded file
	writeFile(t, filepath.Join(dir, "doc.md"), "content\n")

	result, err := Walk(WalkOptions{
		Root:             dir,
		RespectGitIgnore: true,
	})
	if err != nil {
		t.Fatalf("Walk() error: %v", err)
	}
	// doc.md should be found
	if !containsArtifact(result.Artifacts, "doc.md") {
		t.Errorf("doc.md should be in artifacts")
	}
	// Nothing from excluded/ should be found
	for _, a := range result.Artifacts {
		if a.Path == "excluded/secret.md" {
			t.Errorf("excluded/secret.md should be ignored by .gitignore")
		}
	}
}

// TestWalk_SymlinkSubwalkSkippedFiles covers lines 591-595 in walkInternal:
// when FollowSymlinks is true and a symlink points to a directory, the
// sub-walk's Skipped entries must be adjusted and merged into the parent
// result. We use a binary file named to avoid defaultIgnorePaths substring
// matches (e.g., avoid names containing "bin", "dist", "build", etc.).
func TestWalk_SymlinkSubwalkSkippedFiles(t *testing.T) {
	dir := t.TempDir()
	// Create an external directory with a text file and a binary file.
	// The binary file name must NOT contain any defaultIgnorePaths substring
	// (e.g., "bin", "dist", "build", "env", "vendor", etc.).
	externalDir := t.TempDir()
	writeFile(t, filepath.Join(externalDir, "doc.md"), "content\n")
	// Create a binary .md file (null bytes) that will be skipped as binary.
	binContent := make([]byte, 200)
	for i := range binContent {
		if i%3 == 0 {
			binContent[i] = 0x00
		} else {
			binContent[i] = 'A'
		}
	}
	writeFile(t, filepath.Join(externalDir, "blob.md"), string(binContent))

	// Create a symlink to the external directory inside the scan root.
	createSymlink(t, externalDir, filepath.Join(dir, "link"))

	result, err := Walk(WalkOptions{
		Root:           dir,
		FollowSymlinks: true,
	})
	if err != nil {
		t.Fatalf("Walk() error: %v", err)
	}
	// The sub-walk should have found doc.md through the symlink
	found := false
	for _, a := range result.Artifacts {
		if a.Path == "link/doc.md" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("link/doc.md should be in artifacts (followed symlink)")
	}
	// The sub-walk should have skipped blob.md as binary, and the skipped
	// entry should be merged into the parent result with adjusted path.
	skippedFound := false
	for _, s := range result.Skipped {
		if s.Path == "link/blob.md" {
			skippedFound = true
			break
		}
	}
	if !skippedFound {
		t.Errorf("link/blob.md should be in Skipped (binary file through symlink)")
	}
}

// ---------------------------------------------------------------------------
// Archive coverage: non-existent paths, symlink tar entries, ExtractArchivesInPlace errors
// ---------------------------------------------------------------------------

// TestExtractArchive_NonExistentTarGz covers the os.Open error path in
// extractTarGz (lines 213-215).
func TestExtractArchive_NonExistentTarGz(t *testing.T) {
	dir := t.TempDir()
	_, err := ExtractArchive(filepath.Join(dir, "nonexistent.tar.gz"))
	if err == nil {
		t.Error("expected error for non-existent .tar.gz file")
	}
}

// TestExtractArchive_NonExistentTarBz2 covers the os.Open error path in
// extractTarBz2 (lines 234-236).
func TestExtractArchive_NonExistentTarBz2(t *testing.T) {
	dir := t.TempDir()
	_, err := ExtractArchive(filepath.Join(dir, "nonexistent.tar.bz2"))
	if err == nil {
		t.Error("expected error for non-existent .tar.bz2 file")
	}
}

// TestExtractTar_SymlinkEntry covers the tar.TypeSymlink case in extractTar
// (lines 293-295): symlink entries in tar archives should be skipped for
// security.
func TestExtractTar_SymlinkEntry(t *testing.T) {
	dir := t.TempDir()

	// Create a tar.gz archive containing a regular file and a symlink.
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)

	// Regular file
	hdr := &tar.Header{
		Name:     "file.txt",
		Typeflag: tar.TypeReg,
		Size:     7,
		Mode:     0644,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if _, err := tw.Write([]byte("content")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Symlink entry (should be skipped during extraction)
	hdr2 := &tar.Header{
		Name:     "link.txt",
		Typeflag: tar.TypeSymlink,
		Linkname: "file.txt",
		Mode:     0644,
	}
	if err := tw.WriteHeader(hdr2); err != nil {
		t.Fatalf("WriteHeader symlink: %v", err)
	}
	tw.Close()

	// Gzip the tar
	tarPath := filepath.Join(dir, "withsymlink.tar.gz")
	f, err := os.Create(tarPath)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	gw := gzip.NewWriter(f)
	if _, err := gw.Write(tarBuf.Bytes()); err != nil {
		t.Fatalf("gzip Write: %v", err)
	}
	gw.Close()
	f.Close()

	// Extract and verify
	result, err := ExtractArchive(tarPath)
	if err != nil {
		t.Fatalf("ExtractArchive: %v", err)
	}
	defer result.Cleanup()

	// file.txt should be extracted
	foundFile := false
	for _, extracted := range result.Files {
		if extracted == "file.txt" {
			foundFile = true
		}
	}
	if !foundFile {
		t.Errorf("file.txt should be in extracted files")
	}

	// link.txt should NOT be extracted (symlinks are skipped)
	for _, extracted := range result.Files {
		if extracted == "link.txt" {
			t.Errorf("link.txt (symlink) should not be extracted")
		}
	}
}

// TestExtractArchivesInPlace_CorruptArchive covers the error path in
// ExtractArchivesInPlace (lines 346-348): when an archive fails to extract
// after a previous successful extraction, the function should run existing
// cleanups and return an error.
func TestExtractArchivesInPlace_CorruptArchive(t *testing.T) {
	dir := t.TempDir()

	// Create a valid zip file first (so cleanups has an entry).
	validZipPath := filepath.Join(dir, "valid.zip")
	createValidZip(t, validZipPath, "inside.txt", "content\n")

	// Create a file with .zip extension but invalid content.
	corruptPath := filepath.Join(dir, "corrupt.zip")
	writeFile(t, corruptPath, "not a real zip file")

	// ExtractArchivesInPlace should fail on the corrupt zip and run
	// cleanups for the previously-extracted valid zip.
	_, cleanup, err := ExtractArchivesInPlace([]string{validZipPath, corruptPath})
	if err == nil {
		if cleanup != nil {
			cleanup()
		}
		t.Fatal("expected error for corrupt archive in list")
	}
	// cleanup should be nil on error
	if cleanup != nil {
		t.Errorf("cleanup should be nil on error")
	}
}

// createValidZip creates a zip archive at zipPath containing a single file
// with the given name and content.
func createValidZip(t *testing.T, zipPath, fileName, content string) {
	t.Helper()
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("Create zip: %v", err)
	}
	w := zip.NewWriter(f)
	wf, err := w.Create(fileName)
	if err != nil {
		t.Fatalf("Create zip entry: %v", err)
	}
	if _, err := wf.Write([]byte(content)); err != nil {
		t.Fatalf("Write zip entry: %v", err)
	}
	w.Close()
	f.Close()
}

// TestExtractZip_CorruptData covers the io.Copy error path in extractZip
// (line 179-181): a zip file with a valid central directory but corrupted
// compressed data should cause io.Copy to fail during decompression.
func TestExtractZip_CorruptData(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "corrupt_data.zip")

	// Create a valid zip with enough content to ensure deflate compression.
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	wf, err := w.Create("file.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Write enough data to get real compression
	content := bytes.Repeat([]byte("Hello World! "), 100)
	if _, err := wf.Write(content); err != nil {
		t.Fatalf("Write: %v", err)
	}
	w.Close()

	// Corrupt the compressed data (not the central directory at the end).
	// The local file header is 30 bytes + filename length (8 bytes) = 38 bytes.
	// Compressed data starts at offset 38. We flip bytes in the middle of
	// the compressed data to cause a decompression error.
	data := buf.Bytes()
	if len(data) < 60 {
		t.Fatalf("zip too small: %d bytes", len(data))
	}
	// Find a byte in the compressed data region (between local header and
	// central directory) and corrupt it.
	corruptOffset := 45 // well within the compressed data region
	data[corruptOffset] ^= 0xFF

	if err := os.WriteFile(zipPath, data, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Extraction should fail with an io.Copy or decompression error.
	_, err = ExtractArchive(zipPath)
	if err == nil {
		t.Error("expected error for corrupted zip data")
	}
}

// ---------------------------------------------------------------------------
// Gitignore coverage: invalid regex, unclosed bracket, basePath matching
// ---------------------------------------------------------------------------

// TestParseGitIgnore_InvalidRegexPattern covers the compilePattern error
// path in ParseGitIgnore (lines 87-89) and the regexp.Compile error path
// in compilePattern (lines 134-136). The pattern "[]" produces an empty
// character class in regex which is invalid in Go's regexp package.
func TestParseGitIgnore_InvalidRegexPattern(t *testing.T) {
	// "[]" creates an empty character class → invalid regex
	_, err := ParseGitIgnore([]byte("[]\n"), ".")
	if err == nil {
		t.Error("expected error for invalid regex pattern []")
	}
}

// TestGlobToRegex_UnclosedBracket covers the unclosed-bracket path in
// globToRegex (lines 186-190): a pattern containing "[" without a matching
// "]" should treat "[" as a literal character.
func TestGlobToRegex_UnclosedBracket(t *testing.T) {
	// "foo[" has no closing "]" — should produce "foo\[" (valid regex)
	matcher, err := ParseGitIgnore([]byte("foo[\n"), ".")
	if err != nil {
		t.Fatalf("ParseGitIgnore: %v", err)
	}
	// Should match the literal string "foo["
	if !matcher.Match("foo[", false) {
		t.Errorf("foo[ should match literal foo[")
	}
}

// TestMatchDetail_BasePathPrefix covers the basePath prefix-stripping path
// in matchDetail (lines 255-257): when a matcher has a non-empty basePath
// and the path starts with basePath+"/", the prefix should be stripped
// before matching.
func TestMatchDetail_BasePathPrefix(t *testing.T) {
	matcher, err := ParseGitIgnore([]byte("*.tmp\n"), "/some/base")
	if err != nil {
		t.Fatalf("ParseGitIgnore: %v", err)
	}
	// Path with basePath prefix should match after prefix stripping
	if !matcher.Match("/some/base/file.tmp", false) {
		t.Errorf("/some/base/file.tmp should match *.tmp with basePath /some/base")
	}
	// Path without basePath prefix should also match (basePath stripping
	// doesn't apply, but the path "other.tmp" should still match *.tmp)
	if !matcher.Match("other.tmp", false) {
		t.Errorf("other.tmp should match *.tmp")
	}
}

// ---------------------------------------------------------------------------
// Gitignore coverage: LoadFromFile error, LoadGitIgnoreHierarchy error paths
// ---------------------------------------------------------------------------

// TestLoadFromFile_InvalidPattern covers the compilePattern error path in
// LoadFromFile (lines 302-304): a .gitignore file with an invalid pattern
// should cause LoadFromFile to return an error.
func TestLoadFromFile_InvalidPattern(t *testing.T) {
	dir := t.TempDir()
	gitignorePath := filepath.Join(dir, ".gitignore")
	writeFile(t, gitignorePath, "[]\n") // invalid regex pattern

	matcher := &GitIgnoreMatcher{}
	err := matcher.LoadFromFile(gitignorePath)
	if err == nil {
		t.Error("expected error for invalid pattern in .gitignore")
	}
}

// TestLoadGitIgnoreHierarchy_UnreadableGitIgnore covers the os.ReadFile
// error path in LoadGitIgnoreHierarchy (lines 349-350): a .gitignore file
// that exists but cannot be read should be silently skipped.
func TestLoadGitIgnoreHierarchy_UnreadableGitIgnore(t *testing.T) {
	dir := t.TempDir()
	gitignorePath := filepath.Join(dir, ".gitignore")
	writeFile(t, gitignorePath, "*.tmp\n")
	// Remove read permission
	if err := os.Chmod(gitignorePath, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	defer os.Chmod(gitignorePath, 0o644) // restore for cleanup

	// Should not error — unreadable .gitignore is silently skipped
	matchers, err := LoadGitIgnoreHierarchy(dir)
	if err != nil {
		t.Fatalf("LoadGitIgnoreHierarchy: %v", err)
	}
	// The unreadable .gitignore should not produce a matcher
	for _, m := range matchers {
		if m.basePath == dir {
			t.Errorf("should not have a matcher from unreadable .gitignore")
		}
	}
}

// TestLoadGitIgnoreHierarchy_InvalidPattern covers the ParseGitIgnore error
// path in LoadGitIgnoreHierarchy (lines 354-355): a .gitignore file with an
// invalid pattern should be silently skipped.
func TestLoadGitIgnoreHierarchy_InvalidPattern(t *testing.T) {
	dir := t.TempDir()
	gitignorePath := filepath.Join(dir, ".gitignore")
	writeFile(t, gitignorePath, "[]\n") // invalid regex pattern

	// Should not error — unparseable .gitignore is silently skipped
	matchers, err := LoadGitIgnoreHierarchy(dir)
	if err != nil {
		t.Fatalf("LoadGitIgnoreHierarchy: %v", err)
	}
	// The invalid .gitignore should not produce a matcher
	for _, m := range matchers {
		if m.basePath == dir {
			t.Errorf("should not have a matcher from invalid .gitignore")
		}
	}
}
