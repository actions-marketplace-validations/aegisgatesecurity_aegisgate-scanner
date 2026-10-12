// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Core Scanner
// =========================================================================
//
// Combines the detection engine (regex patterns), ML threat detector
// (CharCNN-BiLSTM), and artifact file walker into a unified scanning
// pipeline. Scans files for:
//   - Prompt injection (regex + ML)
//   - PII (US core, US extended, financial, international)
//   - Secrets (65 credential patterns)
//   - XSS (11 patterns)
//   - Compliance violations (35 patterns)
//   - OT/ICS protocol exposure (10 patterns)
//
// The scanner processes artifacts with full-content regex scanning and
// optional ML-based prompt injection detection, providing precise location
// information (line, column) for each finding via byte-offset mapping.
//
// =========================================================================

package scanner

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-scanner/internal/detectors"
	"github.com/aegisgatesecurity/aegisgate-scanner/internal/ml"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/artifacts"
)

// ---------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------

// Severity re-exports detectors.Severity for convenience.
type Severity = detectors.Severity

// Finding represents a single security finding in a scanned artifact.
type Finding struct {
	// Artifact is the path of the file where the finding was detected.
	Artifact string

	// ArtifactClass is the classified type of the artifact.
	ArtifactClass artifacts.ArtifactClass

	// RuleID is the detection rule that triggered (e.g., "secret_aws_key").
	RuleID string

	// Category is the detection category (secrets, pii-us-core, etc.).
	Category string

	// Severity is the risk level (critical, high, medium, low).
	Severity Severity

	// Confidence is a 0-1 confidence score.
	Confidence float64

	// Message is a human-readable description of the finding.
	Message string

	// Line is the 1-based line number where the finding starts.
	Line int

	// Column is the 1-based byte column where the finding starts.
	Column int

	// EndLine is the 1-based line number where the finding ends.
	EndLine int

	// EndColumn is the 1-based byte column where the finding ends.
	EndColumn int

	// MatchedText is the snippet that triggered the detection.
	// Truncated to 200 characters for safety.
	MatchedText string

	// DetectionLayer is the source layer ("regex" or "ml").
	DetectionLayer string

	// MLScore is the raw ML threat score [0, 1], if ML was used.
	MLScore float64

	// MLVariant is the normalization variant that triggered ML detection.
	MLVariant string
}

// ScanOptions controls the scanner behavior.
type ScanOptions struct {
	// EnableML controls whether the ML threat detector is used.
	// Requires CGO_ENABLED=1 and a loaded model.
	EnableML bool

	// MLThreshold is the minimum ML score to report as a finding.
	// If 0, uses the detector's calibrated default.
	MLThreshold float64

	// MinSeverity is the minimum severity to report.
	// Findings below this severity are filtered out.
	MinSeverity Severity

	// MaxFindingsPerFile limits the number of findings per file.
	// 0 = unlimited.
	MaxFindingsPerFile int

	// DisableRules is a list of rule IDs to skip during scanning.
	DisableRules []string

	// Concurrency controls how many files are scanned in parallel.
	// 0 = sequential (default for backwards compatibility).
	// 1 = single worker (same as sequential but with goroutine overhead).
	// >1 = parallel scanning with a worker pool.
	Concurrency int

	// Progress is an optional callback invoked after each file is scanned.
	// It receives (filesScanned, totalFiles). If nil, no progress is reported.
	Progress ProgressFunc
}

// ProgressFunc is called to report scanning progress.
// scanned is the number of files scanned so far, total is the total
// number of files to scan.
type ProgressFunc func(scanned, total int)

// ScanResult holds the results of scanning a set of artifacts.
type ScanResult struct {
	// Findings is the list of security findings.
	Findings []Finding

	// Stats holds summary statistics.
	Stats ScanStats

	// Duration is the total scan time.
	Duration time.Duration
}

// ScanStats holds summary statistics from a scan.
type ScanStats struct {
	FilesScanned      int
	FilesWithFindings int
	TotalFindings     int
	BySeverity        map[Severity]int
	ByCategory        map[string]int
	ByLayer           map[string]int
	MLInferences      int
}

// Scanner is the core scanner that combines detection engines.
type Scanner struct {
	mlDetector *ml.ThreatDetector
	mlEnabled  bool
	mu         sync.Mutex
}

// ---------------------------------------------------------------------
// Scanner lifecycle
// ---------------------------------------------------------------------

// New creates a new Scanner with the given options.
// If EnableML is true and CGO is available, the ML detector is initialized.
func New(opts ScanOptions) (*Scanner, error) {
	s := &Scanner{
		mlEnabled: opts.EnableML,
	}

	if opts.EnableML {
		cfg := ml.DefaultDetectorConfig()
		cfg.Enabled = true
		if opts.MLThreshold > 0 {
			cfg.Threshold = opts.MLThreshold
		}
		s.mlDetector = ml.NewThreatDetector(cfg)
	}

	return s, nil
}

// LoadModel loads the ML model from the given path.
// Only effective if ML was enabled at construction time.
func (s *Scanner) LoadModel(modelPath string) error {
	if s.mlDetector == nil {
		return fmt.Errorf("ML detector not enabled")
	}
	return s.mlDetector.LoadModel(modelPath)
}

// Close releases resources held by the scanner.
func (s *Scanner) Close() error {
	if s.mlDetector != nil {
		return s.mlDetector.Close()
	}
	return nil
}

// ---------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------

// ScanArtifact scans a single artifact and returns findings.
func (s *Scanner) ScanArtifact(art artifacts.Artifact, opts ScanOptions) []Finding {
	var findings []Finding

	// --- Layer 1: Regex detection ---
	regexFindings := s.scanRegex(art)

	// Filter out disabled rules.
	if len(opts.DisableRules) > 0 {
		regexFindings = filterDisabledRules(regexFindings, opts.DisableRules)
	}

	findings = append(findings, regexFindings...)

	// Build per-artifact regex finding map for ML supplementary logic.
	regexLines := buildRegexFindingLines(regexFindings)

	// --- Layer 2: ML detection (supplementary) ---
	// Only run ML if enabled AND the content is substantial enough.
	// ML is supplementary — it catches what regex misses.
	if s.mlEnabled && s.mlDetector != nil && s.mlDetector.IsEnabled() {
		mlFindings := s.scanML(art, regexLines)
		findings = append(findings, mlFindings...)
	}

	// --- Filter by minimum severity ---
	if opts.MinSeverity != "" {
		findings = filterBySeverity(findings, opts.MinSeverity)
	}

	// --- Limit findings per file ---
	if opts.MaxFindingsPerFile > 0 && len(findings) > opts.MaxFindingsPerFile {
		findings = findings[:opts.MaxFindingsPerFile]
	}

	return findings
}

// ScanArtifacts scans multiple artifacts and returns combined results.
func (s *Scanner) ScanArtifacts(arts []artifacts.Artifact, opts ScanOptions) *ScanResult {
	start := time.Now()

	result := &ScanResult{
		Stats: ScanStats{
			BySeverity: make(map[Severity]int),
			ByCategory: make(map[string]int),
			ByLayer:    make(map[string]int),
		},
	}

	if opts.Concurrency > 1 && len(arts) > 1 {
		s.scanConcurrent(arts, opts, result)
	} else {
		s.scanSequential(arts, opts, result)
	}

	result.Duration = time.Since(start)
	return result
}

// scanSequential scans artifacts one at a time.
func (s *Scanner) scanSequential(arts []artifacts.Artifact, opts ScanOptions, result *ScanResult) {
	total := len(arts)
	for _, art := range arts {
		findings := s.ScanArtifact(art, opts)
		s.recordFindings(result, art, findings)
		if opts.Progress != nil {
			opts.Progress(result.Stats.FilesScanned, total)
		}
	}
}

// scanConcurrent scans artifacts using a worker pool.
func (s *Scanner) scanConcurrent(arts []artifacts.Artifact, opts ScanOptions, result *ScanResult) {
	total := len(arts)

	type fileResult struct {
		Index    int
		Findings []Finding
		Art      artifacts.Artifact
	}

	numWorkers := opts.Concurrency
	if numWorkers > len(arts) {
		numWorkers = len(arts)
	}

	jobs := make(chan int, len(arts))
	results := make(chan fileResult, len(arts))

	// Start workers.
	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				findings := s.ScanArtifact(arts[idx], opts)
				results <- fileResult{Index: idx, Findings: findings, Art: arts[idx]}
			}
		}()
	}

	// Send jobs.
	for i := range arts {
		jobs <- i
	}
	close(jobs)

	// Wait for all workers to finish, then close results.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results.
	for fr := range results {
		s.recordFindings(result, fr.Art, fr.Findings)
		if opts.Progress != nil {
			s.mu.Lock()
			opts.Progress(result.Stats.FilesScanned, total)
			s.mu.Unlock()
		}
	}
}

// recordFindings adds findings to the result and updates stats.
func (s *Scanner) recordFindings(result *ScanResult, art artifacts.Artifact, findings []Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result.Stats.FilesScanned++

	if len(findings) > 0 {
		result.Stats.FilesWithFindings++
		result.Stats.TotalFindings += len(findings)

		for _, f := range findings {
			result.Stats.BySeverity[f.Severity]++
			result.Stats.ByCategory[f.Category]++
			result.Stats.ByLayer[f.DetectionLayer]++
			if f.DetectionLayer == "ml" {
				result.Stats.MLInferences++
			}
		}

		result.Findings = append(result.Findings, findings...)
	}
}

// ---------------------------------------------------------------------
// Regex detection
// ---------------------------------------------------------------------

// scanRegex runs the regex detection engine on an artifact.
//
// Scans the full content in a single pass and converts byte offsets to
// line/column positions via byteOffsetToLineCol. This is dramatically
// faster than the previous line-by-line approach which ran DetectAll
// (257 patterns) on every line separately — O(N×P) vs O(P) where N is
// the line count and P is the pattern count.
//
// The full-content scan is a strict superset of line-by-line scanning:
// any match on a single line is also a match in the full content at the
// same byte position. Multi-line patterns (spanning line boundaries) are
// ONLY caught by the full-content scan, so this approach also improves
// detection coverage.
func (s *Scanner) scanRegex(art artifacts.Artifact) []Finding {
	matches := detectors.DetectAll(art.Content)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]Finding, 0, len(matches))
	for _, m := range matches {
		line, col := byteOffsetToLineCol(art.Content, m.Index)
		endLine, endCol := byteOffsetToLineCol(art.Content, m.End)

		finding := Finding{
			Artifact:       art.Path,
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
		}
		findings = append(findings, finding)
	}

	return findings
}

// ---------------------------------------------------------------------
// ML detection
// ---------------------------------------------------------------------

// scanML runs the ML threat detector on an artifact.
// ML is supplementary — it scans content segments that regex didn't flag.
func (s *Scanner) scanML(art artifacts.Artifact, regexLines map[int]bool) []Finding {
	var findings []Finding

	// Scan content in segments (paragraphs or significant chunks).
	segments := splitSegments(art.Content, 512)

	for _, seg := range segments {
		// Skip segments that already have regex findings — ML is supplementary.
		if hasRegexFindingLine(regexLines, seg.StartLine) {
			continue
		}

		score := s.mlDetector.Detect(seg.Text)
		if score.IsThreat {
			finding := Finding{
				Artifact:       art.Path,
				ArtifactClass:  art.Class,
				RuleID:         "ml_prompt_injection",
				Category:       "ml-prompt-injection",
				Severity:       detectors.SeverityHigh,
				Confidence:     score.Score,
				Message:        "ML detector: potential prompt injection detected",
				Line:           seg.StartLine,
				Column:         1,
				EndLine:        seg.EndLine,
				EndColumn:      len(seg.Text) - strings.LastIndex(seg.Text, "\n"),
				MatchedText:    truncate(seg.Text, 200),
				DetectionLayer: "ml",
				MLScore:        score.Score,
				MLVariant:      score.Variant,
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// segment represents a chunk of text within an artifact.
type segment struct {
	Text      string
	StartLine int
	EndLine   int
}

// splitSegments splits content into segments of approximately maxLen bytes
// at paragraph boundaries. Each segment tracks its line range.
func splitSegments(content string, maxLen int) []segment {
	var segments []segment
	lines := strings.Split(content, "\n")

	var current strings.Builder
	currentStart := 1
	currentLen := 0

	for i, line := range lines {
		lineLen := len(line) + 1 // +1 for newline
		if currentLen+lineLen > maxLen && current.Len() > 0 {
			segments = append(segments, segment{
				Text:      current.String(),
				StartLine: currentStart,
				EndLine:   i,
			})
			current.Reset()
			currentStart = i + 1
			currentLen = 0
		}
		current.WriteString(line)
		current.WriteString("\n")
		currentLen += lineLen
	}

	if current.Len() > 0 {
		segments = append(segments, segment{
			Text:      current.String(),
			StartLine: currentStart,
			EndLine:   len(lines),
		})
	}

	return segments
}

// byteOffsetToLineCol converts a byte offset in content to a 1-based
// line and column position.
func byteOffsetToLineCol(content string, offset int) (line, col int) {
	if offset < 0 {
		return 1, 1
	}
	if offset > len(content) {
		offset = len(content)
	}

	line = 1
	col = 1
	for i := 0; i < offset; i++ {
		if content[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

// truncate shortens a string to maxLen characters, appending "..." if truncated.
// Returns the original string if maxLen is negative (treated as no limit).
// Returns empty string if maxLen is 0.
func truncate(s string, maxLen int) string {
	if maxLen < 0 {
		return s
	}
	if maxLen == 0 {
		return ""
	}
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// formatRegexMessage creates a human-readable message for a regex finding.
func formatRegexMessage(ruleID string, severity Severity) string {
	return fmt.Sprintf("%s: detected %s pattern", severity, ruleID)
}

// buildRegexFindingLines creates a per-artifact map of lines with regex findings.
// This replaces the package-level global to be safe for concurrent scanning.
func buildRegexFindingLines(findings []Finding) map[int]bool {
	lines := make(map[int]bool)
	for _, f := range findings {
		if f.DetectionLayer != "regex" {
			continue
		}
		for line := f.Line; line <= f.EndLine; line++ {
			lines[line] = true
		}
	}
	return lines
}

// hasRegexFindingLine checks if a specific line has regex findings.
func hasRegexFindingLine(regexLines map[int]bool, line int) bool {
	return regexLines[line]
}

// filterBySeverity removes findings below the minimum severity.
func filterBySeverity(findings []Finding, min Severity) []Finding {
	rank := map[Severity]int{
		detectors.SeverityCritical: 4,
		detectors.SeverityHigh:     3,
		detectors.SeverityMedium:   2,
		detectors.SeverityLow:      1,
	}

	minRank, ok := rank[min]
	if !ok {
		return findings // unknown severity, don't filter
	}

	filtered := findings[:0]
	for _, f := range findings {
		if r, ok := rank[f.Severity]; ok && r >= minRank {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// filterDisabledRules removes findings whose rule ID is in the disabled list.
func filterDisabledRules(findings []Finding, disabled []string) []Finding {
	if len(disabled) == 0 {
		return findings
	}
	disabledSet := make(map[string]bool, len(disabled))
	for _, r := range disabled {
		disabledSet[r] = true
	}
	filtered := findings[:0]
	for _, f := range findings {
		if !disabledSet[f.RuleID] {
			filtered = append(filtered, f)
		}
	}
	return filtered
}
