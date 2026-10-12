// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Programmatic API / SDK
// =========================================================================
//
// Provides a clean Go API for embedding AegisGate Scanner into other
// applications. Wraps the scanner package with a simplified interface.
//
// Usage:
//
//   sc, err := api.NewScanner()
//   if err != nil { ... }
//   defer sc.Close()
//
//   result, err := sc.ScanPath("/path/to/artifacts")
//   if err != nil { ... }
//
//   result, err = sc.ScanContent("agent_skill.py", content)
//   if err != nil { ... }
//
//   result, err = sc.ScanReader("config.yaml", reader)
//   if err != nil { ... }
//
// =========================================================================

package api

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aegisgatesecurity/aegisgate-scanner/internal/detectors"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/artifacts"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/scanner"
)

// ---------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------

// ScannerOptions configures the API scanner.
type ScannerOptions struct {
	// EnableML controls ML-based detection.
	EnableML bool

	// MLThreshold is the minimum ML score (0-1) to report.
	MLThreshold float64

	// MinSeverity is the minimum severity to report.
	// Options: "critical", "high", "medium", "low".
	// Empty = report all.
	MinSeverity string

	// MaxFindingsPerFile limits findings per file (0 = unlimited).
	MaxFindingsPerFile int

	// DisableRules is a list of rule IDs to skip.
	DisableRules []string

	// Concurrency controls parallel scanning (0 = sequential).
	Concurrency int

	// IgnorePaths are glob patterns to exclude from path scans.
	IgnorePaths []string

	// MaxFileSize is the max file size in bytes (0 = default 10MB).
	MaxFileSize int64

	// Extensions restricts scanning to specific extensions.
	// Empty = all supported.
	Extensions []string
}

// APIScanner is the public API scanner for programmatic embedding.
type APIScanner struct {
	scanner *scanner.Scanner
	opts    ScannerOptions
}

// ScanResult holds the results of a scan operation.
type ScanResult = scanner.ScanResult

// Finding represents a single security finding.
type Finding = scanner.Finding

// ---------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------

// NewScanner creates a new API scanner with default options.
func NewScanner() (*APIScanner, error) {
	return NewScannerWithOptions(ScannerOptions{
		EnableML: false, // Default: regex-only for library use.
	})
}

// NewScannerWithOptions creates a new API scanner with custom options.
func NewScannerWithOptions(opts ScannerOptions) (*APIScanner, error) {
	scanOpts := scanner.ScanOptions{
		EnableML:           opts.EnableML,
		MLThreshold:        opts.MLThreshold,
		MinSeverity:        parseAPISeverity(opts.MinSeverity),
		MaxFindingsPerFile: opts.MaxFindingsPerFile,
		DisableRules:       opts.DisableRules,
		Concurrency:        opts.Concurrency,
	}

	sc, err := scanner.New(scanOpts)
	if err != nil {
		return nil, fmt.Errorf("create scanner: %w", err)
	}

	return &APIScanner{
		scanner: sc,
		opts:    opts,
	}, nil
}

// Close releases resources held by the scanner.
func (a *APIScanner) Close() error {
	return a.scanner.Close()
}

// ---------------------------------------------------------------------
// Scanning methods
// ---------------------------------------------------------------------

// ScanPath scans a directory path for security threats.
// Returns a ScanResult with all findings.
func (a *APIScanner) ScanPath(path string) (*ScanResult, error) {
	if path == "" {
		return nil, fmt.Errorf("path cannot be empty")
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	// Build walk options.
	walkOpts := artifacts.WalkOptions{
		Root:        absPath,
		IgnorePaths: a.opts.IgnorePaths,
		Extensions:  a.opts.Extensions,
	}
	if a.opts.MaxFileSize > 0 {
		walkOpts.MaxFileSize = a.opts.MaxFileSize
	}

	// Walk files.
	walkResult, err := artifacts.Walk(walkOpts)
	if err != nil {
		return nil, fmt.Errorf("walk directory: %w", err)
	}

	if len(walkResult.Artifacts) == 0 {
		return &ScanResult{
			Findings: []Finding{},
			Stats: scanner.ScanStats{
				BySeverity: make(map[detectors.Severity]int),
				ByCategory: make(map[string]int),
				ByLayer:    make(map[string]int),
			},
		}, nil
	}

	// Scan artifacts.
	scanOpts := a.buildScanOptions()
	return a.scanner.ScanArtifacts(walkResult.Artifacts, scanOpts), nil
}

// ScanContent scans raw content bytes with a virtual filename.
// The filename is used for classification and reporting.
func (a *APIScanner) ScanContent(filename string, content []byte) (*ScanResult, error) {
	if filename == "" {
		return nil, fmt.Errorf("filename cannot be empty")
	}

	art := artifacts.ReadArtifactFromContent(filename, content)

	scanOpts := a.buildScanOptions()
	findings := a.scanner.ScanArtifact(art, scanOpts)

	return buildResult(findings), nil
}

// ScanReader scans content from an io.Reader with a virtual filename.
// The reader is fully read into memory before scanning.
func (a *APIScanner) ScanReader(filename string, r io.Reader) (*ScanResult, error) {
	if filename == "" {
		return nil, fmt.Errorf("filename cannot be empty")
	}

	content, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read content: %w", err)
	}

	return a.ScanContent(filename, content)
}

// ScanFiles scans a specific list of file paths.
// Unlike ScanPath, this does not walk a directory — it scans only
// the given files.
func (a *APIScanner) ScanFiles(paths []string) (*ScanResult, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no file paths provided")
	}

	var arts []artifacts.Artifact

	for _, p := range paths {
		absPath, err := filepath.Abs(p)
		if err != nil {
			continue
		}

		// Read and create artifact.
		content, lines, err := readArtifactFile(absPath)
		if err != nil {
			continue
		}

		art := artifacts.Artifact{
			Path:    p,
			AbsPath: absPath,
			Class:   artifacts.ClassifyFile(p),
			Size:    int64(len(content)),
			Content: content,
			Lines:   lines,
		}
		arts = append(arts, art)
	}

	if len(arts) == 0 {
		return &ScanResult{
			Findings: []Finding{},
			Stats: scanner.ScanStats{
				BySeverity: make(map[detectors.Severity]int),
				ByCategory: make(map[string]int),
				ByLayer:    make(map[string]int),
			},
		}, nil
	}

	scanOpts := a.buildScanOptions()
	return a.scanner.ScanArtifacts(arts, scanOpts), nil
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// buildScanOptions converts API options to scanner options.
func (a *APIScanner) buildScanOptions() scanner.ScanOptions {
	return scanner.ScanOptions{
		EnableML:           a.opts.EnableML,
		MLThreshold:        a.opts.MLThreshold,
		MinSeverity:        parseAPISeverity(a.opts.MinSeverity),
		MaxFindingsPerFile: a.opts.MaxFindingsPerFile,
		DisableRules:       a.opts.DisableRules,
		Concurrency:        a.opts.Concurrency,
	}
}

// buildResult creates a ScanResult from a slice of findings.
func buildResult(findings []Finding) *ScanResult {
	stats := scanner.ScanStats{
		FilesScanned:  1,
		TotalFindings: len(findings),
		BySeverity:    make(map[detectors.Severity]int),
		ByCategory:    make(map[string]int),
		ByLayer:       make(map[string]int),
	}
	if len(findings) > 0 {
		stats.FilesWithFindings = 1
	}
	for _, f := range findings {
		stats.BySeverity[f.Severity]++
		stats.ByCategory[f.Category]++
		stats.ByLayer[f.DetectionLayer]++
	}
	return &ScanResult{
		Findings: findings,
		Stats:    stats,
	}
}

// parseAPISeverity converts a string to detectors.Severity.
func parseAPISeverity(s string) detectors.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return detectors.SeverityCritical
	case "high":
		return detectors.SeverityHigh
	case "medium":
		return detectors.SeverityMedium
	case "low":
		return detectors.SeverityLow
	default:
		return ""
	}
}

// readArtifactFile reads a file and returns its content and line count.
func readArtifactFile(path string) (string, int, error) {
	data, err := readFileContent(path)
	if err != nil {
		return "", 0, err
	}

	content := strings.TrimPrefix(string(data), "\xEF\xBB\xBF")
	lines := strings.Count(content, "\n")
	if len(content) > 0 && !strings.HasSuffix(content, "\n") {
		lines++
	}

	return content, lines, nil
}

// readFileContent reads a file's content into bytes.
func readFileContent(path string) ([]byte, error) {
	return os.ReadFile(path)
}
