// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Diff Scanning Tests
// =========================================================================
//
// Tests for GetChangedFiles() and FilterArtifactsByFileList().
// Uses a temporary git repository to test real git diff behavior.
//
// =========================================================================

package scanner

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------
// Git test helpers
// ---------------------------------------------------------------------

// setupGitRepo creates a temporary git repository with a base branch
// and some changes on HEAD for testing diff scanning.
func setupGitRepo(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	// Initialize git repo.
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@test.com")
	runGit(t, dir, "config", "user.name", "Test")

	// Create base branch with initial files.
	writeFile(t, dir, "file1.txt", "initial content")
	writeFile(t, dir, "file2.txt", "initial content")
	writeFile(t, dir, "old.txt", "to be deleted")

	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "initial commit")

	// Create main branch at the initial commit (before any feature changes).
	runGit(t, dir, "branch", "main")

	// Create and switch to a feature branch.
	runGit(t, dir, "checkout", "-b", "feature")

	// Make changes: modify file1, add file3, delete old.txt.
	writeFile(t, dir, "file1.txt", "modified content")
	writeFile(t, dir, "file3.txt", "new file")
	os.Remove(filepath.Join(dir, "old.txt"))

	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "feature changes")

	return dir
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_DATE=2024-01-01T00:00:00", "GIT_COMMITTER_DATE=2024-01-01T00:00:00")
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %s failed in %s: %v", strings.Join(args, " "), dir, err)
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir for %s: %v", name, err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// ---------------------------------------------------------------------
// GetChangedFiles tests
// ---------------------------------------------------------------------

func TestGetChangedFiles_Basic(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := setupGitRepo(t)
	files, err := GetChangedFiles("main", dir)
	if err != nil {
		t.Fatalf("GetChangedFiles error: %v", err)
	}

	if len(files) == 0 {
		t.Fatal("expected changed files, got 0")
	}

	sort.Strings(files)

	// Should contain file1.txt (modified), file3.txt (added), old.txt (deleted).
	foundFile1 := false
	foundFile3 := false
	foundOld := false
	for _, f := range files {
		switch f {
		case "file1.txt":
			foundFile1 = true
		case "file3.txt":
			foundFile3 = true
		case "old.txt":
			foundOld = true
		}
	}

	if !foundFile1 {
		t.Error("should detect modified file1.txt")
	}
	if !foundFile3 {
		t.Error("should detect new file3.txt")
	}
	if !foundOld {
		t.Error("should detect deleted old.txt")
	}
}

func TestGetChangedFiles_NoChanges(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@test.com")
	runGit(t, dir, "config", "user.name", "Test")
	writeFile(t, dir, "file.txt", "content")
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "initial")
	runGit(t, dir, "branch", "main")

	// Create a feature branch with no changes.
	runGit(t, dir, "checkout", "-b", "feature")

	// No changes on HEAD vs main.
	files, err := GetChangedFiles("main", dir)
	if err != nil {
		t.Fatalf("GetChangedFiles error: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 changed files, got %d: %v", len(files), files)
	}
}

func TestGetChangedFiles_EmptyBaseBranch(t *testing.T) {
	_, err := GetChangedFiles("", "/tmp")
	if err == nil {
		t.Error("GetChangedFiles should error on empty base branch")
	}
}

func TestGetChangedFiles_EmptyRepoRoot(t *testing.T) {
	_, err := GetChangedFiles("main", "")
	if err == nil {
		t.Error("GetChangedFiles should error on empty repo root")
	}
}

func TestGetChangedFiles_InvalidRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	// No git repo initialized.
	_, err := GetChangedFiles("main", dir)
	if err == nil {
		t.Error("GetChangedFiles should error on non-git directory")
	}
}

func TestGetChangedFilesCmd(t *testing.T) {
	cmd := GetChangedFilesCmd("main")
	expected := []string{"git", "diff", "--name-only", "main...HEAD"}
	if len(cmd) != len(expected) {
		t.Fatalf("command length mismatch: got %v, want %v", cmd, expected)
	}
	for i := range cmd {
		if cmd[i] != expected[i] {
			t.Errorf("cmd[%d] = %s, want %s", i, cmd[i], expected[i])
		}
	}
}

// ---------------------------------------------------------------------
// FilterArtifactsByFileList tests
// ---------------------------------------------------------------------

func TestFilterArtifactsByFileList_Basic(t *testing.T) {
	artifacts := []string{
		"src/main.go",
		"src/util.go",
		"docs/readme.md",
		"config.yaml",
	}
	fileList := []string{
		"src/main.go",
		"config.yaml",
	}

	result := FilterArtifactsByFileList(artifacts, fileList)
	if len(result) != 2 {
		t.Fatalf("expected 2 filtered artifacts, got %d: %v", len(result), result)
	}

	sort.Strings(result)
	if result[0] != "config.yaml" || result[1] != "src/main.go" {
		t.Errorf("filtered artifacts = %v, want [config.yaml, src/main.go]", result)
	}
}

func TestFilterArtifactsByFileList_EmptyFileList(t *testing.T) {
	artifacts := []string{"a.txt", "b.txt"}
	result := FilterArtifactsByFileList(artifacts, nil)
	if len(result) != 2 {
		t.Errorf("empty file list should return all artifacts, got %d", len(result))
	}
}

func TestFilterArtifactsByFileList_NoMatches(t *testing.T) {
	artifacts := []string{"a.txt", "b.txt"}
	fileList := []string{"c.txt", "d.txt"}
	result := FilterArtifactsByFileList(artifacts, fileList)
	if len(result) != 0 {
		t.Errorf("no matches should return empty, got %d: %v", len(result), result)
	}
}

func TestFilterArtifactsByFileList_CaseInsensitive(t *testing.T) {
	artifacts := []string{"Src/Main.go"}
	fileList := []string{"src/main.go"}
	result := FilterArtifactsByFileList(artifacts, fileList)
	if len(result) != 1 {
		t.Errorf("case-insensitive match should find 1 artifact, got %d", len(result))
	}
}

func TestFilterArtifactsByFileList_EmptyArtifacts(t *testing.T) {
	result := FilterArtifactsByFileList(nil, []string{"a.txt"})
	if len(result) != 0 {
		t.Errorf("empty artifacts should return empty, got %d", len(result))
	}
}
