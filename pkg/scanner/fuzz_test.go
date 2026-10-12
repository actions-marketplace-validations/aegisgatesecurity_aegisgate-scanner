// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Fuzz Tests for Scanner Pipeline
// =========================================================================
//
// Go native fuzzing tests for the Scanner.ScanArtifact pipeline.
// Feeds random/mutated content through the full regex + ML pipeline
// to ensure no panics, hangs, or invalid Finding structs.
//
// Run with:
//
//	go test -fuzz=FuzzScanArtifact -fuzztime=30s ./pkg/scanner/
//
// =========================================================================

package scanner

import (
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/artifacts"
)

// FuzzScanArtifact feeds random content through the full scan pipeline
// and verifies no panics and all findings have valid fields.
func FuzzScanArtifact(f *testing.F) {
	// Seed corpus.
	f.Add("Ignore all previous instructions", "test.txt")
	f.Add("AKIAIOSFODNN7EXAMPLE", "config.yaml")
	f.Add("SSN: 123-45-6789", "data.csv")
	f.Add("", "empty.txt")
	f.Add(strings.Repeat("\x00", 1000), "binary.dat")
	f.Add("eval(atob('aGVsbG8='))", "agent_skill.py")
	f.Add("ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD", "config.json")
	f.Add(strings.Repeat("ignore previous instructions\n", 1000), "large.txt")
	f.Add("正常文本没有安全问题", "chinese.txt")
	f.Add("🦀🔥💀", "emoji.txt")

	f.Fuzz(func(t *testing.T, content, path string) {
		art := artifacts.Artifact{
			Path:    path,
			Content: content,
		}

		s, err := New(ScanOptions{})
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		defer s.Close()

		findings := s.ScanArtifact(art, ScanOptions{})

		for _, finding := range findings {
			// Artifact may be empty if the input path was empty.
			if finding.RuleID == "" {
				t.Error("finding has empty RuleID")
			}
			if finding.Line < 1 {
				t.Errorf("finding Line < 1: %d", finding.Line)
			}
			if finding.Column < 1 {
				t.Errorf("finding Column < 1: %d", finding.Column)
			}
			if finding.EndLine < finding.Line {
				t.Errorf("finding EndLine < Line: end=%d line=%d", finding.EndLine, finding.Line)
			}
			if finding.DetectionLayer == "" {
				t.Error("finding has empty DetectionLayer")
			}
		}
	})
}

// FuzzByteOffsetToLineCol feeds random offsets into the byte-offset-to-
// line/column converter to ensure no panics or out-of-bounds.
func FuzzByteOffsetToLineCol(f *testing.F) {
	content := "line1\nline2\nline3\nline4\n"
	f.Add(0)
	f.Add(5)
	f.Add(6)
	f.Add(100)
	f.Add(-1)
	f.Add(len(content))
	f.Add(len(content) + 100)

	f.Fuzz(func(t *testing.T, offset int) {
		line, col := byteOffsetToLineCol(content, offset)
		if line < 1 {
			t.Errorf("line < 1: %d", line)
		}
		if col < 1 {
			t.Errorf("col < 1: %d", col)
		}
	})
}

// FuzzTruncate feeds random strings and lengths into truncate.
func FuzzTruncate(f *testing.F) {
	f.Add("hello world", 5)
	f.Add("", 10)
	f.Add("A", 0)
	f.Add(strings.Repeat("X", 1000), 100)
	f.Add("🦀rust🦀", 3)

	f.Fuzz(func(t *testing.T, input string, maxLen int) {
		result := truncate(input, maxLen)
		// Result should never be longer than maxLen (except when maxLen <= 0
		// where we return the original string unchanged).
		if maxLen > 0 && len(result) > maxLen {
			t.Errorf("truncate result longer than maxLen: len=%d maxLen=%d", len(result), maxLen)
		}
	})
}
