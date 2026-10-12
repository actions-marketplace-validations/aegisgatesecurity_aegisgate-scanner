// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWalk_UnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root — permission tests don't work")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "readable.txt"), []byte("content"), 0644)
	os.WriteFile(filepath.Join(dir, "unreadable.txt"), []byte("content"), 0644)
	os.Chmod(filepath.Join(dir, "unreadable.txt"), 0000)
	defer os.Chmod(filepath.Join(dir, "unreadable.txt"), 0644)

	result, err := Walk(WalkOptions{Root: dir})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	if len(result.Artifacts) < 1 {
		t.Error("expected at least 1 artifact")
	}
	if result.Stats.SkippedFiles < 1 {
		t.Error("expected at least 1 skipped file")
	}
}

func TestWalk_BrokenSymlink_Cov(t *testing.T) {
	dir := t.TempDir()
	os.Symlink("/nonexistent/target", filepath.Join(dir, "broken.txt"))

	result, err := Walk(WalkOptions{Root: dir})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	_ = result
}

func TestWalk_SymlinkToDirectoryFollowed_Cov(t *testing.T) {
	dir := t.TempDir()
	// Create a real directory OUTSIDE the scan root
	externalDir := t.TempDir()
	os.WriteFile(filepath.Join(externalDir, "file.txt"), []byte("content"), 0644)
	// Add a file with binary content (null bytes) that will be skipped as binary
	binContent := make([]byte, 200)
	for i := range binContent {
		if i%3 == 0 {
			binContent[i] = 0x00
		} else {
			binContent[i] = 'A'
		}
	}
	os.WriteFile(filepath.Join(externalDir, "binary.txt"), binContent, 0644)

	// Create a symlink to the external directory inside the scan root
	os.Symlink(externalDir, filepath.Join(dir, "link"))

	result, err := Walk(WalkOptions{
		Root:           dir,
		FollowSymlinks: true,
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if result.Stats.TotalFiles < 1 {
		t.Error("expected at least 1 file through symlink")
	}
	found := false
	for _, art := range result.Artifacts {
		if strings.Contains(art.Path, "file.txt") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find file.txt through symlink")
	}
}
