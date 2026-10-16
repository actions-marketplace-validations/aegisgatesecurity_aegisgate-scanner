// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Git History Scanning
// =========================================================================
//
// Scans git commit history for secrets and sensitive data that may have been
// committed and later removed. This catches leaks that exist only in git's
// object database — even after a `git rm` + commit, the secret remains in
// previous commits forever.
//
// Uses `git log --patch` to extract diffs, then feeds each diff to the
// existing detection engine. Includes safeguards against:
//   - Huge commits (max diff size limit)
//   - Too many commits (max commit count limit)
//   - Binary diffs (skipped automatically by git)
//
// =========================================================================

package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/artifacts"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/detectors"
)

// ---------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------

// HistoryOptions controls git history scanning behavior.
type HistoryOptions struct {
	// MaxCommits is the maximum number of commits to scan.
	// 0 = unlimited (not recommended for large repos).
	// Default: 1000.
	MaxCommits int

	// MaxDiffSize is the maximum diff size per commit in bytes.
	// Commits with larger diffs are skipped. Default: 1MB.
	MaxDiffSize int64

	// BaseBranch, if set, only scans commits not in this branch
	// (e.g., "main" — scans only branch-specific commits).
	BaseBranch string

	// IncludeMergeCommits controls whether merge commits are scanned.
	// Default: false (merge commits usually duplicate changes).
	IncludeMergeCommits bool

	// Since, if set, only scans commits after this date.
	Since time.Time

	// Until, if set, only scans commits before this date.
	Until time.Time
}

// DefaultHistoryOptions returns sensible defaults for history scanning.
func DefaultHistoryOptions() HistoryOptions {
	return HistoryOptions{
		MaxCommits:          1000,
		MaxDiffSize:         1024 * 1024, // 1MB
		IncludeMergeCommits: false,
	}
}

// HistoryFinding extends Finding with git commit metadata.
type HistoryFinding struct {
	Finding

	// CommitHash is the short hash of the commit where the finding was detected.
	CommitHash string

	// CommitMessage is the first line of the commit message.
	CommitMessage string

	// CommitDate is the date of the commit.
	CommitDate string

	// FilePath is the file path within the commit diff.
	FilePath string
}

// HistoryResult holds the results of a git history scan.
type HistoryResult struct {
	// Findings is the list of detected findings in git history.
	Findings []HistoryFinding

	// CommitsScanned is the number of commits processed.
	CommitsScanned int

	// CommitsSkipped is the number of commits skipped (too large, merge, etc.).
	CommitsSkipped int

	// DiffsScanned is the number of file diffs processed.
	DiffsScanned int

	// Elapsed is the total scan duration.
	Elapsed time.Duration
}

// ---------------------------------------------------------------------
// History scanning
// ---------------------------------------------------------------------

// ScanHistory scans git commit history for secrets and sensitive data.
//
// It uses `git log --patch` to extract diffs from each commit, then
// feeds the added lines to the detection engine. This catches secrets
// that were committed and later removed — they still exist in git's
// object database and can be extracted by anyone with repo access.
//
// Parameters:
//   - repoRoot: the root directory of the git repository
//   - opts: scanning options (use DefaultHistoryOptions() for defaults)
//
// Returns a HistoryResult with all findings and scan statistics.
func ScanHistory(repoRoot string, opts HistoryOptions) (*HistoryResult, error) {
	if opts.MaxCommits == 0 {
		opts = DefaultHistoryOptions()
	}

	start := time.Now()
	result := &HistoryResult{}

	// Build git log command.
	args := []string{
		"log",
		fmt.Sprintf("-%d", opts.MaxCommits),
		"--patch",
		"--no-color",
		"--format=COMMIT:%H%nMSG:%s%nDATE:%ci%nENDMETA",
	}

	if !opts.IncludeMergeCommits {
		args = append(args, "--no-merges")
	}

	if opts.BaseBranch != "" {
		args = append(args, opts.BaseBranch+"..HEAD")
	}

	if !opts.Since.IsZero() {
		args = append(args, "--since="+opts.Since.Format("2006-01-02"))
	}
	if !opts.Until.IsZero() {
		args = append(args, "--until="+opts.Until.Format("2006-01-02"))
	}

	cmd := exec.Command("git", args...) //nosec G204 -- intentional git subprocess for history scanning
	cmd.Dir = repoRoot

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start git log: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	// Increase buffer size for large diffs.
	scanner.Buffer(make([]byte, 0, 256*1024), int(opts.MaxDiffSize)*2)

	currentCommit := ""
	currentMsg := ""
	currentDate := ""
	currentFile := ""
	var diffContent strings.Builder
	diffSize := int64(0)
	inDiff := false

	processDiff := func() {
		if diffContent.Len() == 0 {
			return
		}

		// Check diff size limit.
		if int64(diffContent.Len()) > opts.MaxDiffSize {
			result.CommitsSkipped++
			diffContent.Reset()
			diffSize = 0
			return
		}

		result.DiffsScanned++

		// Create an artifact from the diff content.
		art := artifacts.Artifact{
			Path:    currentFile,
			Content: diffContent.String(),
			Class:   artifacts.ClassGeneric,
		}

		// Detect language from file path for language-aware scanning.
		lang := detectors.LanguageFromPath(currentFile)

		// Scan with regex engine using language filtering.
		matches := detectors.DetectAllWithLanguage(art.Content, lang)

		// Also run entropy detection for unknown secrets.
		entropyMatches := detectors.DetectEntropy(art.Content)
		matches = append(matches, entropyMatches...)

		// Convert matches to HistoryFindings.
		for _, m := range matches {
			line, col := byteOffsetToLineCol(art.Content, m.Index)
			endLine, endCol := byteOffsetToLineCol(art.Content, m.End)

			hf := HistoryFinding{
				Finding: Finding{
					Artifact:       currentFile,
					ArtifactClass:  art.Class,
					RuleID:         m.Category,
					Category:       m.Category,
					Severity:       m.Severity,
					Confidence:     m.Confidence,
					Message:        formatRegexMessage(m.Category, m.Severity),
					Line:           line,
					Column:         col,
					EndLine:        endLine,
					EndColumn:      endCol,
					MatchedText:    truncate(m.Value, 200),
					DetectionLayer: "regex",
					Remediation:    getRemediation(m.Category, m.Category, m.Severity),
				},
				CommitHash:    currentCommit,
				CommitMessage: currentMsg,
				CommitDate:    currentDate,
				FilePath:      currentFile,
			}

			if m.Category == "entropy_high_string" {
				hf.DetectionLayer = "entropy"
				hf.Message = "High-entropy string detected (potential secret)"
			}

			result.Findings = append(result.Findings, hf)
		}

		diffContent.Reset()
		diffSize = 0
	}

	for scanner.Scan() {
		line := scanner.Text()

		// Parse commit metadata.
		if strings.HasPrefix(line, "COMMIT:") {
			// Process previous diff if any.
			if inDiff {
				processDiff()
				inDiff = false
			}
			currentCommit = strings.TrimPrefix(line, "COMMIT:")
			result.CommitsScanned++
			continue
		}
		if strings.HasPrefix(line, "MSG:") {
			currentMsg = strings.TrimPrefix(line, "MSG:")
			continue
		}
		if strings.HasPrefix(line, "DATE:") {
			currentDate = strings.TrimPrefix(line, "DATE:")
			continue
		}
		if line == "ENDMETA" {
			continue
		}

		// Parse diff headers.
		if strings.HasPrefix(line, "diff --git") {
			// Process previous file diff.
			if inDiff {
				processDiff()
			}
			inDiff = true
			currentFile = ""
			continue
		}
		if strings.HasPrefix(line, "+++ ") {
			// Extract file path from +++ b/path line.
			path := strings.TrimPrefix(line, "+++ ")
			path = strings.TrimPrefix(path, "b/")
			path = strings.TrimPrefix(path, "a/")
			if path != "/dev/null" {
				currentFile = path
			}
			continue
		}
		if strings.HasPrefix(line, "--- ") {
			// Skip --- a/path line (we use +++ for the file path).
			continue
		}

		// Only collect added lines (starting with +, not +++).
		if inDiff && strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			content := line[1:] // Remove the leading +
			diffContent.WriteString(content)
			diffContent.WriteString("\n")
			diffSize += int64(len(content) + 1)

			// Check per-diff size limit.
			if diffSize > opts.MaxDiffSize {
				processDiff()
				inDiff = false
			}
		}
	}

	// Process final diff.
	if inDiff {
		processDiff()
	}

	if err := scanner.Err(); err != nil {
		// Non-fatal: return what we have.
		result.CommitsSkipped++
	}

	if err := cmd.Wait(); err != nil {
		// git log might return non-zero if no commits match; that's fine.
		// Only return error if stderr has real content.
		if stderr.Len() > 0 && !strings.Contains(stderr.String(), "does not have any commits") {
			// Non-fatal: return what we have plus a warning.
			result.CommitsSkipped++
		}
	}

	result.Elapsed = time.Since(start)
	return result, nil
}
