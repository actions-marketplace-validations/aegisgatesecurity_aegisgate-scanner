// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Diff Scanning Support
// =========================================================================
//
// Provides git diff-based scanning: instead of scanning the entire
// directory tree, only files that have changed relative to a base
// branch are scanned.
//
// Uses `git diff --name-only base_branch...HEAD` to determine changed
// files. Falls back to scanning all files if git is not available.
//
// =========================================================================

package scanner

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// ---------------------------------------------------------------------
// Diff scanning
// ---------------------------------------------------------------------

// GetChangedFiles returns the list of files that have changed between
// the base branch and HEAD in the given repository root.
// It uses `git diff --name-only base_branch...HEAD` to determine the
// changed files.
//
// Parameters:
//   - baseBranch: the base branch to compare against (e.g., "main", "origin/main")
//   - repoRoot: the root directory of the git repository
//
// Returns:
//   - A slice of file paths relative to repoRoot
//   - An error if git fails or the repository is invalid
func GetChangedFiles(baseBranch, repoRoot string) ([]string, error) {
	if baseBranch == "" {
		return nil, fmt.Errorf("base branch cannot be empty")
	}
	if repoRoot == "" {
		return nil, fmt.Errorf("repository root cannot be empty")
	}

	// Ensure git is available.
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("git not found in PATH: %w", err)
	}

	// Run git diff --name-only base_branch...HEAD
	cmd := exec.Command(gitPath, "diff", "--name-only", baseBranch+"...HEAD")
	cmd.Dir = repoRoot

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		stderrStr := strings.TrimSpace(stderr.String())
		if stderrStr != "" {
			return nil, fmt.Errorf("git diff failed: %s: %w", stderrStr, err)
		}
		return nil, fmt.Errorf("git diff failed: %w", err)
	}

	// Parse output: one file per line.
	output := strings.TrimSpace(stdout.String())
	if output == "" {
		return []string{}, nil
	}

	lines := strings.Split(output, "\n")
	files := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			files = append(files, filepath.ToSlash(line))
		}
	}

	return files, nil
}

// GetChangedFilesCmd returns the git command that would be used to get
// changed files. This is primarily for testing and debugging.
func GetChangedFilesCmd(baseBranch string) []string {
	return []string{"git", "diff", "--name-only", baseBranch + "...HEAD"}
}

// FilterArtifactsByFileList filters a slice of artifacts to only include
// those whose path matches one of the files in the given file list.
// The matching is case-insensitive and compares relative paths.
func FilterArtifactsByFileList(artifacts []string, fileList []string) []string {
	if len(fileList) == 0 {
		return artifacts
	}

	fileSet := make(map[string]bool, len(fileList))
	for _, f := range fileList {
		fileSet[strings.ToLower(filepath.ToSlash(f))] = true
	}

	result := make([]string, 0, len(artifacts))
	for _, a := range artifacts {
		if fileSet[strings.ToLower(filepath.ToSlash(a))] {
			result = append(result, a)
		}
	}
	return result
}
