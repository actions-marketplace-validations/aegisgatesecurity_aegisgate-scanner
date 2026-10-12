// SPDX-License-Identifier: Apache-2.0
package scanner

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestScanHistory_BasicRepo(t *testing.T) {
	// Create a temp git repo with a secret in history
	dir := t.TempDir()

	// Init git repo
	runGitHelper(t, dir, "init")
	runGitHelper(t, dir, "config", "user.email", "test@test.com")
	runGitHelper(t, dir, "config", "user.name", "Test")

	// Commit a file with a secret
	secretFile := filepath.Join(dir, "config.py")
	os.WriteFile(secretFile, []byte("api_key = 'AKIAIOSFODNN7EXAMPLE'\n"), 0644)
	runGitHelper(t, dir, "add", ".")
	runGitHelper(t, dir, "commit", "-m", "add config with secret")

	// Remove the secret and commit again
	os.WriteFile(secretFile, []byte("api_key = os.environ.get('API_KEY')\n"), 0644)
	runGitHelper(t, dir, "add", ".")
	runGitHelper(t, dir, "commit", "-m", "remove hardcoded secret")

	// Scan history
	result, err := ScanHistory(dir, DefaultHistoryOptions())
	if err != nil {
		t.Fatalf("ScanHistory failed: %v", err)
	}

	if result.CommitsScanned == 0 {
		t.Error("expected at least 1 commit scanned")
	}

	// Should find the AWS key in the first commit
	found := false
	for _, f := range result.Findings {
		if f.RuleID == "secret_aws_key" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find secret_aws_key in git history")
	}
}

func TestScanHistory_EmptyRepo(t *testing.T) {
	dir := t.TempDir()
	runGitHelper(t, dir, "init")
	runGitHelper(t, dir, "config", "user.email", "test@test.com")
	runGitHelper(t, dir, "config", "user.name", "Test")

	// No commits
	result, err := ScanHistory(dir, DefaultHistoryOptions())
	if err != nil {
		t.Fatalf("ScanHistory failed: %v", err)
	}
	if result.CommitsScanned != 0 {
		t.Errorf("expected 0 commits, got %d", result.CommitsScanned)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestScanHistory_NotARepo(t *testing.T) {
	dir := t.TempDir()
	// Not a git repo
	result, err := ScanHistory(dir, DefaultHistoryOptions())
	// Should not crash, may return error or empty result
	if err != nil {
		// That's fine
		return
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestScanHistory_MaxCommitsLimit(t *testing.T) {
	dir := t.TempDir()
	runGitHelper(t, dir, "init")
	runGitHelper(t, dir, "config", "user.email", "test@test.com")
	runGitHelper(t, dir, "config", "user.name", "Test")

	// Create 5 commits with different content
	for i := 0; i < 5; i++ {
		f := filepath.Join(dir, "file.txt")
		os.WriteFile(f, []byte("content line "+string(rune('a'+i))+"\n"), 0644)
		runGitHelper(t, dir, "add", ".")
		runGitHelper(t, dir, "commit", "-m", "commit")
	}

	opts := DefaultHistoryOptions()
	opts.MaxCommits = 3
	result, err := ScanHistory(dir, opts)
	if err != nil {
		t.Fatalf("ScanHistory failed: %v", err)
	}
	if result.CommitsScanned > 3 {
		t.Errorf("expected at most 3 commits, got %d", result.CommitsScanned)
	}
}

func TestScanHistory_CleanRepo(t *testing.T) {
	dir := t.TempDir()
	runGitHelper(t, dir, "init")
	runGitHelper(t, dir, "config", "user.email", "test@test.com")
	runGitHelper(t, dir, "config", "user.name", "Test")

	// Commit a clean file
	os.WriteFile(filepath.Join(dir, "clean.py"), []byte("print('hello world')\n"), 0644)
	runGitHelper(t, dir, "add", ".")
	runGitHelper(t, dir, "commit", "-m", "clean commit")

	result, err := ScanHistory(dir, DefaultHistoryOptions())
	if err != nil {
		t.Fatalf("ScanHistory failed: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings in clean repo, got %d", len(result.Findings))
		for _, f := range result.Findings {
			t.Logf("  finding: %s in %s", f.RuleID, f.FilePath)
		}
	}
}

func runGitHelper(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Stderr = nil
	cmd.Stdout = nil
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %v failed: %v", args, err)
	}
}
