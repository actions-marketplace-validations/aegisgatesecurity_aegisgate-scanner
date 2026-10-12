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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-scanner/internal/detectors"
	"github.com/aegisgatesecurity/aegisgate-scanner/internal/ml"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/artifacts"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/cache"
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

	// Remediation provides actionable guidance on how to fix the finding.
	// Populated by getRemediation() based on category and rule ID.
	Remediation string
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

	// Cache is an optional content-hash cache. If set, scan results are
	// cached by SHA-256(content). Files with unchanged content skip
	// detection entirely on subsequent scans.
	// Filters (severity, disable-rules, baseline, suppressions) are
	// applied post-cache, so changing those does NOT invalidate the cache.
	Cache *cache.Cache
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

	// CacheHits is the number of files served from cache (skipped scanning).
	// CacheMisses is the number of files that required a full scan.
	// Both are 0 when caching is not enabled.
	CacheHits   int
	CacheMisses int
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

// ComputeCacheHeader builds a cache.CacheHeader for use with the
// content-hash cache. It captures the scanner version, a hash of all
// pattern definitions, and whether ML is enabled. Any change to
// patterns or scanner version will invalidate cached results.
//
// scannerVersion should be the build-time version string (e.g., "0.3.0").
func ComputeCacheHeader(scannerVersion string, mlEnabled bool) cache.CacheHeader {
	defs := detectors.AllPatternDefs()
	patternStrs := make([]string, len(defs))
	for i, d := range defs {
		patternStrs[i] = d.Name + "|" + d.Regex
	}
	return cache.CacheHeader{
		Version:        cache.CacheVersion,
		ScannerVersion: scannerVersion,
		PatternSetHash: cache.PatternSetHash(patternStrs),
		MLEnabled:      mlEnabled,
	}
}

// ---------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------

// ScanArtifact scans a single artifact and returns findings.
//
// If a cache is provided in opts.Cache and the artifact content is
// non-empty, the scanner first checks the cache for a stored result
// keyed by SHA-256(content). On a cache hit, the raw findings are
// returned from cache and only option-based filters are re-applied
// (severity, disable-rules, max-findings, inline suppressions). On a
// cache miss, all detection layers run and the raw findings are stored
// in the cache before returning.
func (s *Scanner) ScanArtifact(art artifacts.Artifact, opts ScanOptions) []Finding {
	// Try cache first. If enabled and content is non-empty, check for
	// a cached result before running any detection layers.
	if opts.Cache != nil && art.Content != "" {
		contentHash := cache.ContentHash(art.Content)
		if cached := opts.Cache.Get(contentHash); cached != nil {
			// Cache hit — convert cached findings and apply filters.
			findings := fromCacheFindings(cached, art)
			return s.applyFilters(art, findings, opts)
		}
		// Cache miss — run full detection, then cache raw findings.
		rawFindings := s.detectAll(art)
		opts.Cache.Put(contentHash, toCacheFindings(rawFindings), art.Size)
		return s.applyFilters(art, rawFindings, opts)
	}

	// No cache — run detection and apply filters.
	rawFindings := s.detectAll(art)
	return s.applyFilters(art, rawFindings, opts)
}

// detectAll runs all detection layers (regex, entropy, ML) and returns
// raw, unfiltered findings. This is the expensive part that caching avoids.
func (s *Scanner) detectAll(art artifacts.Artifact) []Finding {
	var findings []Finding

	// --- Layer 1: Regex detection (language-aware) ---
	regexFindings := s.scanRegex(art)

	// --- Layer 1b: Known example suppression ---
	// Suppress findings that match known documentation/test values.
	// This is part of raw detection (not option-based filtering) because
	// it depends only on the content, not on scan options.
	regexFindings = s.suppressKnownExamples(regexFindings)

	findings = append(findings, regexFindings...)

	// --- Layer 1c: Entropy detection (unknown secrets) ---
	entropyFindings := s.scanEntropy(art, regexFindings)
	findings = append(findings, entropyFindings...)

	// Build per-artifact regex finding map for ML supplementary logic.
	regexLines := buildRegexFindingLines(regexFindings)

	// --- Layer 2: ML detection (supplementary) ---
	if s.mlEnabled && s.mlDetector != nil && s.mlDetector.IsEnabled() {
		mlFindings := s.scanML(art, regexLines)
		findings = append(findings, mlFindings...)
	}

	return findings
}

// applyFilters applies option-based filtering to raw findings.
// These filters are NOT part of the cache key — changing them does not
// invalidate the cache. This includes: disabled rules, severity threshold,
// max findings per file, and inline suppressions.
func (s *Scanner) applyFilters(art artifacts.Artifact, findings []Finding, opts ScanOptions) []Finding {
	// Filter out disabled rules.
	if len(opts.DisableRules) > 0 {
		findings = filterDisabledRules(findings, opts.DisableRules)
	}

	// --- Filter by minimum severity ---
	if opts.MinSeverity != "" {
		findings = filterBySeverity(findings, opts.MinSeverity)
	}

	// --- Limit findings per file ---
	if opts.MaxFindingsPerFile > 0 && len(findings) > opts.MaxFindingsPerFile {
		findings = findings[:opts.MaxFindingsPerFile]
	}

	// --- Apply inline suppressions ---
	if art.Content != "" {
		suppressions := ParseSuppressions(art.Content)
		if len(suppressions) > 0 {
			findings = ApplySuppressions(findings, suppressions)
		}
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

	// Collect cache stats if caching was enabled.
	if opts.Cache != nil {
		hits, misses := opts.Cache.Stats()
		result.Stats.CacheHits = hits
		result.Stats.CacheMisses = misses
	}

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
// Cache conversion helpers
// ---------------------------------------------------------------------

// toCacheFindings converts scanner Finding slice to cache-friendly format.
// Only detection-layer fields are preserved — option-based fields (like
// artifact path) are re-applied on cache hit via fromCacheFindings.
func toCacheFindings(findings []Finding) []cache.CacheFinding {
	if len(findings) == 0 {
		return nil
	}
	result := make([]cache.CacheFinding, len(findings))
	for i, f := range findings {
		result[i] = cache.CacheFinding{
			RuleID:         f.RuleID,
			Category:       f.Category,
			Severity:       string(f.Severity),
			Confidence:     f.Confidence,
			Message:        f.Message,
			Line:           f.Line,
			Column:         f.Column,
			EndLine:        f.EndLine,
			EndColumn:      f.EndColumn,
			MatchedText:    f.MatchedText,
			DetectionLayer: f.DetectionLayer,
		}
	}
	return result
}

// fromCacheFindings converts cached findings back to scanner Finding slice,
// re-applying the artifact path and class from the current artifact.
func fromCacheFindings(cached []cache.CacheFinding, art artifacts.Artifact) []Finding {
	if len(cached) == 0 {
		return nil
	}
	findings := make([]Finding, len(cached))
	for i, c := range cached {
		findings[i] = Finding{
			Artifact:       art.Path,
			ArtifactClass:  art.Class,
			RuleID:         c.RuleID,
			Category:       c.Category,
			Severity:       Severity(c.Severity),
			Confidence:     c.Confidence,
			Message:        c.Message,
			Line:           c.Line,
			Column:         c.Column,
			EndLine:        c.EndLine,
			EndColumn:      c.EndColumn,
			MatchedText:    c.MatchedText,
			DetectionLayer: c.DetectionLayer,
		}
	}
	return findings
}

// ---------------------------------------------------------------------
// Regex detection
// ---------------------------------------------------------------------

// scanRegex runs the regex detection engine on an artifact.
//
// Uses language-aware scanning: detects the file's language from its
// extension and filters patterns accordingly. This reduces false positives
// (e.g., Python patterns don't run on YAML files) and improves performance
// (fewer regex passes per file).
//
// Uses merged regex alternation for one-pass scanning per category
// (10x fewer regex calls than the previous sequential approach).
func (s *Scanner) scanRegex(art artifacts.Artifact) []Finding {
	// Detect language from file path for language-aware filtering.
	lang := detectors.LanguageFromPath(art.Path)
	matches := detectors.DetectAllWithLanguage(art.Content, lang)
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
			Remediation:    getRemediation(m.Category, m.Category, m.Severity),
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
				Remediation:    getRemediation("ml-prompt-injection", "ml_prompt_injection", detectors.SeverityHigh),
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

	// Binary search on precomputed newline positions for O(log n) lookup.
	// This replaces the original O(n) linear scan that dominated CPU time
	// on large files with many findings.
	newlines := getNewlinePositions(content)
	idx := sort.SearchInts(newlines, offset)
	line = idx + 1
	if idx == 0 {
		col = offset + 1
	} else {
		col = offset - newlines[idx-1]
	}
	return line, col
}

// newlineCache caches newline position slices by content to avoid
// recomputing for the same content (e.g., when called for both Index and End).
var newlineCache sync.Map

func getNewlinePositions(content string) []int {
	// Check cache first.
	if v, ok := newlineCache.Load(content); ok {
		return v.([]int)
	}

	var positions []int
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' {
			positions = append(positions, i)
		}
	}

	newlineCache.Store(content, positions)
	return positions
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

// suppressKnownExamples filters out findings that match known documentation
// example values, test tokens, and placeholder data. Suppressed findings
// have their confidence reduced to 0.1 but are still returned (just with
// lower confidence) so they remain visible in verbose output.
func (s *Scanner) suppressKnownExamples(findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}
	filtered := findings[:0]
	for _, f := range findings {
		if detectors.IsKnownExample(f.MatchedText) || detectors.IsExampleByContent(f.MatchedText) {
			// Reduce confidence but keep the finding.
			f.Confidence = 0.1
			f.Message = f.Message + " (known example/test value)"
		}
		filtered = append(filtered, f)
	}
	return filtered
}

// scanEntropy runs Shannon entropy detection on an artifact to catch
// unknown secrets that don't match any regex pattern. It avoids
// double-reporting regions already flagged by regex.
func (s *Scanner) scanEntropy(art artifacts.Artifact, regexFindings []Finding) []Finding {
	entropyMatches := detectors.DetectEntropy(art.Content)
	if len(entropyMatches) == 0 {
		return nil
	}

	// Build a set of byte ranges already covered by regex findings
	// to avoid duplicate detections.
	type rangeKey struct{ start, end int }
	covered := make(map[rangeKey]bool, len(regexFindings))
	for _, f := range regexFindings {
		// Convert line/col back to approximate byte offset.
		// We use the finding's line to mark coverage at line granularity.
		covered[rangeKey{f.Line, f.EndLine}] = true
	}

	var findings []Finding
	for _, m := range entropyMatches {
		line, col := byteOffsetToLineCol(art.Content, m.Index)
		endLine, endCol := byteOffsetToLineCol(art.Content, m.End)

		// Skip if this region is already covered by a regex finding.
		if covered[rangeKey{line, endLine}] {
			continue
		}

		findings = append(findings, Finding{
			Artifact:       art.Path,
			ArtifactClass:  art.Class,
			RuleID:         "entropy_high_string",
			Category:       "entropy",
			Severity:       m.Severity,
			Confidence:     m.Confidence,
			Message:        "High-entropy string detected (potential unknown secret)",
			Line:           line,
			Column:         col,
			EndLine:        endLine,
			EndColumn:      endCol,
			MatchedText:    truncate(m.Value, 200),
			DetectionLayer: "entropy",
			Remediation:    "Review this high-entropy string. If it is a secret, remove it and rotate it. If it is benign, add an inline suppression: // aegisgate-ignore: entropy_high_string",
		})
	}

	return findings
}
