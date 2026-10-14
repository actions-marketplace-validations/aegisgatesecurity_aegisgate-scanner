// SPDX-License-Identifier: Apache-2.0
// Provenance: github.com/aegisgatesecurity/aegisgate-platform/pkg/response/detectors (v4.0.0)
// =========================================================================
// AegisGate Platform - Detector Engine
// =========================================================================
//
// Shared detection engine that compiles PatternDef slices into regexp.Regexp
// and scans text for matches. This is the core runtime that all 7 detector
// packages use.
//
// v0.3.0 improvements:
//   - Regex merging: patterns within a category are merged into a single
//     alternation regex for one-pass scanning (10x fewer regex calls).
//   - Language-aware filtering: patterns with Languages metadata are only
//     run on files matching those languages.
//   - Entropy detection: Shannon entropy analysis catches unknown secrets.
//
// =========================================================================

package detectors

import (
	"fmt"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------
// Compiled pattern types
// ---------------------------------------------------------------------

// compiledPattern holds a pre-compiled regex pattern with its metadata.
type compiledPattern struct {
	Name        string
	Severity    Severity
	Confidence  float64
	Compiled    *regexp.Regexp
	Description string
	Languages   []Language
	Keywords    []string
}

// mergedCategory holds a category's patterns merged into a single alternation
// regex for high-performance one-pass scanning. If merging fails (regex too
// complex), it falls back to sequential scanning via individual patterns.
type mergedCategory struct {
	name       string
	combined   *regexp.Regexp    // merged alternation regex (nil if merge failed)
	groupNames []string          // pattern name for each capturing group
	patterns   []compiledPattern // fallback: individual patterns
}

// compilePatterns compiles a slice of PatternDef into compiledPattern slices.
// Panics on invalid regex — all patterns must be valid at init time.
func compilePatterns(defs []PatternDef) []compiledPattern {
	patterns := make([]compiledPattern, len(defs))
	for i, def := range defs {
		re, err := regexp.Compile(def.Regex)
		if err != nil {
			panic("detectors: invalid regex for " + def.Name + ": " + err.Error())
		}
		patterns[i] = compiledPattern{
			Name:        def.Name,
			Severity:    def.Severity,
			Confidence:  1.0,
			Compiled:    re,
			Description: def.Description,
			Languages:   def.Languages,
			Keywords:    extractKeywords(def.Regex),
		}
	}
	return patterns
}

// maxMergedRegexSize is the maximum length of a merged regex string.
// Beyond this, the merged regex NFA becomes too complex and sequential
// scanning is faster. Empirically determined: compliance (16K chars)
// is 4x slower merged, while dangerous-functions (1.6K chars) is 2x faster.
const maxMergedRegexSize = 3000

// mergeCategory attempts to merge all patterns in a category into a single
// alternation regex with named capturing groups. This enables one-pass
// scanning instead of N passes.
//
// The merged regex looks like: (?P<p1>regex1)|(?P<p2>regex2)|...
//
// Group names are guaranteed unique by using the pattern index.
// If the merged regex exceeds maxMergedRegexSize or fails to compile,
// the function returns a mergedCategory with combined=nil, and callers
// fall back to sequential scanning.
func mergeCategory(name string, patterns []compiledPattern) mergedCategory {
	mc := mergedCategory{
		name:     name,
		patterns: patterns,
	}

	if len(patterns) == 0 {
		return mc
	}

	// Build alternation with uniquely-named groups.
	var parts []string
	groupNames := make([]string, 0, len(patterns))
	totalLen := 0

	for i, p := range patterns {
		groupName := fmt.Sprintf("p%d", i)
		groupNames = append(groupNames, p.Name)

		part := fmt.Sprintf("(?P<%s>(?:%s))", groupName, p.Compiled.String())
		totalLen += len(part) + 1 // +1 for the | separator
		parts = append(parts, part)

		// Early exit if we exceed the size limit.
		if totalLen > maxMergedRegexSize {
			return mc // combined stays nil → sequential fallback
		}
	}

	merged := strings.Join(parts, "|")

	// Final size check after join.
	if len(merged) > maxMergedRegexSize {
		return mc
	}

	re, err := regexp.Compile(merged)
	if err != nil {
		return mc
	}

	mc.combined = re
	mc.groupNames = groupNames
	return mc
}

// detectWithPatterns scans text using pre-compiled patterns and returns matches.
// Uses merged regex when available, falls back to sequential scanning.
func detectWithPatterns(text string, patterns []compiledPattern, category string) []Match {
	return detectWithPatternsFiltered(text, patterns, category, LangAny)
}

// mergedRegexMinTextSize is the minimum text size (bytes) for using the
// merged regex. Below this, sequential scanning is faster due to less
// submatch processing overhead.
const mergedRegexMinTextSize = 4096

// detectWithPatternsFiltered scans text with optional language filtering.
// If lang is LangAny, all patterns are used. Otherwise, only patterns that
// have no language restriction (Languages is nil/empty) OR include the
// specified language are used.
func detectWithPatternsFiltered(text string, patterns []compiledPattern, category string, lang Language) []Match {
	if len(text) == 0 || len(patterns) == 0 {
		return nil
	}

	// Filter patterns by language.
	filtered := filterByLanguage(patterns, lang)
	if len(filtered) == 0 {
		return nil
	}

	start := time.Now()
	var matches []Match

	// Use merged regex only for larger texts where the one-pass benefit
	// outweighs submatch processing overhead. For small texts, sequential
	// scanning is faster.
	useMerged := len(text) >= mergedRegexMinTextSize && lang == LangAny
	if useMerged {
		merged := getMergedCategory(category)
		if merged != nil && merged.combined != nil {
			matches = detectWithMerged(text, merged)
		} else {
			matches = detectSequential(text, filtered)
		}
	} else if lang != LangAny {
		// Language-filtered scan: use sequential (merged doesn't support filtering well).
		matches = detectSequential(text, filtered)
	} else {
		// Small text: sequential is faster.
		matches = detectSequential(text, filtered)
	}

	// Sort by index (mirrors Lens behavior)
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Index < matches[j].Index
	})

	_ = time.Since(start) // available for future metrics

	return matches
}

// detectSequential runs each pattern individually against the text.
func detectSequential(text string, patterns []compiledPattern) []Match {
	var matches []Match
	for _, p := range patterns {
		indices := p.Compiled.FindAllStringIndex(text, -1)
		for _, idx := range indices {
			value := text[idx[0]:idx[1]]
			if len(value) > 200 {
				value = value[:200] + "..."
			}
			matches = append(matches, Match{
				Category:   p.Name,
				Severity:   p.Severity,
				Confidence: p.Confidence,
				Value:      value,
				Index:      idx[0],
				End:        idx[1],
			})
		}
	}
	return matches
}

// detectWithMerged uses the merged alternation regex for one-pass scanning.
// It uses FindAllStringSubmatchIndex to determine which named group matched.
func detectWithMerged(text string, mc *mergedCategory) []Match {
	submatches := mc.combined.FindAllStringSubmatchIndex(text, -1)
	if len(submatches) == 0 {
		return nil
	}

	var matches []Match
	numGroups := mc.combined.NumSubexp()

	for _, sm := range submatches {
		// sm[0:2] is the full match. sm[2:] are submatch groups.
		// Find which group matched (has non-nil indices).
		matchStart := sm[0]
		matchEnd := sm[1]

		// Extract the matched value.
		value := text[matchStart:matchEnd]
		if len(value) > 200 {
			value = value[:200] + "..."
		}

		// Find which named group matched.
		groupIdx := -1
		for i := 0; i < numGroups; i++ {
			base := 2 + i*2
			if base+1 < len(sm) && sm[base] >= 0 {
				groupIdx = i
				break
			}
		}

		var patternName string
		var severity Severity
		var confidence float64

		if groupIdx >= 0 && groupIdx < len(mc.patterns) {
			patternName = mc.patterns[groupIdx].Name
			severity = mc.patterns[groupIdx].Severity
			confidence = mc.patterns[groupIdx].Confidence
		} else {
			// Fallback: use the merged match without group identification.
			patternName = mc.name
			severity = SeverityMedium
			confidence = 0.8
		}

		matches = append(matches, Match{
			Category:   patternName,
			Severity:   severity,
			Confidence: confidence,
			Value:      value,
			Index:      matchStart,
			End:        matchEnd,
		})
	}

	return matches
}

// filterByLanguage returns only patterns applicable to the given language.
func filterByLanguage(patterns []compiledPattern, lang Language) []compiledPattern {
	if lang == LangAny {
		return patterns
	}

	var filtered []compiledPattern
	for _, p := range patterns {
		if len(p.Languages) == 0 {
			// No language restriction = applies to all.
			filtered = append(filtered, p)
			continue
		}
		for _, l := range p.Languages {
			if l == lang || l == LangAny {
				filtered = append(filtered, p)
				break
			}
		}
	}
	return filtered
}

// filterMatchesByLanguage filters merged-regex matches to only include
// those whose source pattern is language-appropriate.
func filterMatchesByLanguage(matches []Match, mc *mergedCategory, allowed []compiledPattern) []Match {
	allowedSet := make(map[string]bool, len(allowed))
	for _, p := range allowed {
		allowedSet[p.Name] = true
	}

	var filtered []Match
	for _, m := range matches {
		if allowedSet[m.Category] {
			filtered = append(filtered, m)
		}
	}
	return filtered
}

// ---------------------------------------------------------------------
// Merged category cache
// ---------------------------------------------------------------------

var (
	mergedCache   = make(map[string]*mergedCategory)
	mergedCacheMu sync.RWMutex
)

// getMergedCategory returns the cached merged category for the given name,
// building it on first access.
func getMergedCategory(category string) *mergedCategory {
	mergedCacheMu.RLock()
	mc, ok := mergedCache[category]
	mergedCacheMu.RUnlock()
	if ok {
		return mc
	}

	mergedCacheMu.Lock()
	defer mergedCacheMu.Unlock()

	// Double-check after acquiring write lock.
	if mc, ok := mergedCache[category]; ok {
		return mc
	}

	// Find the patterns for this category.
	var patterns []compiledPattern
	switch category {
	case "secrets":
		patterns = CompiledSecretPatterns
	case "xss":
		patterns = CompiledXSSPatterns
	case "pii-us-core":
		patterns = CompiledPIIUSCorePatterns
	case "pii-us-extended":
		patterns = CompiledPIIUSExtendedPatterns
	case "pii-financial":
		patterns = CompiledPIIFinancialPatterns
	case "pii-international":
		patterns = CompiledPIIInternationalPatterns
	case "compliance":
		patterns = CompiledCompliancePatterns
	case "dangerous-function":
		patterns = CompiledDangerousFunctionPatterns
	case "ot-protocols":
		patterns = CompiledOTProtocolPatterns
	case "rag":
		patterns = CompiledRAGPatterns
	case "prompt-leakage":
		patterns = CompiledPromptLeakagePatterns
	default:
		return nil
	}

	mc2 := mergeCategory(category, patterns)
	mergedCache[category] = &mc2
	return &mc2
}

// ---------------------------------------------------------------------
// Public detection API
// ---------------------------------------------------------------------

// detectAllThreshold is the minimum content size (bytes) for concurrent
// category scanning. Below this threshold, goroutine overhead exceeds the
// benefit of parallelism, so categories are scanned sequentially.
const detectAllThreshold = 8192 // 8KB

// lineScanThreshold is the minimum content size (bytes) for line-by-line
// scanning with keyword pre-filtering. Above this, the engine splits text
// into lines and only runs patterns whose extracted keywords appear on each
// line, dramatically reducing wasted regex work on large files.
const lineScanThreshold = 65536 // 64KB — above this, use line-by-line scanning

// extractKeywords extracts literal substrings from a regex pattern string.
// These keywords are used for pre-filtering lines before running the full
// regex, so only lines containing at least one keyword are scanned by a
// given pattern.
//
// Rules:
//   - Only a-z, A-Z, 0-9 are literal characters; everything else flushes
//     the current literal run.
//   - Escape sequences (\x) skip the next character.
//   - Character class contents [...] are skipped entirely.
//   - Minimum keyword length is 3 characters.
//   - Keywords must contain at least one letter (not just digits).
//   - Keywords are returned lowercase and deduplicated.
//   - regexp.LiteralPrefix() is also consulted; if the prefix is >= 3 chars
//     it is included as a keyword.
func extractKeywords(pattern string) []string {
	seen := make(map[string]bool)
	var keywords []string

	addKeyword := func(s string) {
		if len(s) < 3 {
			return
		}
		hasLetter := false
		for _, ch := range s {
			if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
				hasLetter = true
				break
			}
		}
		if !hasLetter {
			return
		}
		lower := strings.ToLower(s)
		if !seen[lower] {
			seen[lower] = true
			keywords = append(keywords, lower)
		}
	}

	// Walk the pattern, collecting literal runs.
	var buf strings.Builder
	i := 0
	for i < len(pattern) {
		ch := pattern[i]
		switch {
		case ch == '\\':
			// Escape sequence: flush current buffer, skip next char.
			addKeyword(buf.String())
			buf.Reset()
			i += 2 // skip \ and the escaped char
			continue
		case ch == '[':
			// Character class: flush current buffer, skip until ']'.
			addKeyword(buf.String())
			buf.Reset()
			i++
			for i < len(pattern) && pattern[i] != ']' {
				if pattern[i] == '\\' {
					i++ // skip escaped char inside class
				}
				i++
			}
			if i < len(pattern) {
				i++ // skip the ']'
			}
			continue
		case (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9'):
			buf.WriteByte(ch)
			i++
		default:
			// Non-literal: flush current buffer.
			addKeyword(buf.String())
			buf.Reset()
			i++
		}
	}
	addKeyword(buf.String())

	// Also consult regexp.LiteralPrefix via a compiled version of the pattern.
	if re, err := regexp.Compile(pattern); err == nil {
		litPrefix, complete := re.LiteralPrefix()
		if len(litPrefix) >= 3 && !complete {
			// LiteralPrefix returns the longest literal prefix of the regex.
			// Filter to alphanumeric-only and add as keyword.
			var lb strings.Builder
			for _, ch := range litPrefix {
				if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
					lb.WriteRune(ch)
				} else {
					break
				}
			}
			addKeyword(lb.String())
		}
	}

	return keywords
}

// detectAllByLines scans large text using line-by-line analysis with keyword
// pre-filtering. Only patterns whose extracted keywords appear on a given
// line are run against that line, dramatically reducing wasted regex work.
//
// Lines are processed in parallel using a worker pool sized to NumCPU.
func detectAllByLines(text string, lang Language) []Match {
	// Gather all patterns across all categories, including custom patterns.
	customMu.RLock()
	customSnapshot := customPatterns
	customMu.RUnlock()

	allPatterns := make([]compiledPattern, 0, 300)
	allPatterns = append(allPatterns, CompiledSecretPatterns...)
	allPatterns = append(allPatterns, CompiledXSSPatterns...)
	allPatterns = append(allPatterns, CompiledPIIUSCorePatterns...)
	allPatterns = append(allPatterns, CompiledPIIUSExtendedPatterns...)
	allPatterns = append(allPatterns, CompiledPIIFinancialPatterns...)
	allPatterns = append(allPatterns, CompiledPIIInternationalPatterns...)
	allPatterns = append(allPatterns, CompiledCompliancePatterns...)
	allPatterns = append(allPatterns, CompiledDangerousFunctionPatterns...)
	allPatterns = append(allPatterns, CompiledOTProtocolPatterns...)
	allPatterns = append(allPatterns, CompiledRAGPatterns...)
	allPatterns = append(allPatterns, CompiledPromptLeakagePatterns...)
	allPatterns = append(allPatterns, customSnapshot...)

	// Apply language filtering once.
	filtered := filterByLanguage(allPatterns, lang)

	// Separate patterns into keyword-filtered and always-run groups.
	// Keyword patterns run line-by-line (only on lines containing their keywords).
	// Always-run patterns run on the full text in parallel (they have no
	// keyword pre-filter, but full-text scanning is efficient for these
	// mostly simple patterns like SSN, phone, and credit card).
	var keywordPatterns []compiledPattern
	var alwaysRunPatterns []compiledPattern
	for _, p := range filtered {
		if len(p.Keywords) > 0 {
			keywordPatterns = append(keywordPatterns, p)
		} else {
			alwaysRunPatterns = append(alwaysRunPatterns, p)
		}
	}

	// Split text into lines, tracking byte offsets. We use a compact
	// representation: two parallel slices for text and offset to reduce
	// struct allocation overhead.
	var lineTexts []string
	var lineOffsets []int
	start := 0
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			lineTexts = append(lineTexts, text[start:i])
			lineOffsets = append(lineOffsets, start)
			start = i + 1
		}
	}
	if start < len(text) {
		lineTexts = append(lineTexts, text[start:])
		lineOffsets = append(lineOffsets, start)
	}

	numLines := len(lineTexts)
	if numLines == 0 {
		return nil
	}

	// Process lines in parallel using batch-based work distribution
	// (no channels — each worker gets a contiguous slice of lines).
	numWorkers := runtime.NumCPU()
	if numWorkers < 1 {
		numWorkers = 1
	}
	if numWorkers > numLines {
		numWorkers = numLines
	}

	batchSize := (numLines + numWorkers - 1) / numWorkers
	results := make([][]Match, numWorkers)

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		batchStart := w * batchSize
		batchEnd := batchStart + batchSize
		if batchEnd > numLines {
			batchEnd = numLines
		}
		if batchStart >= batchEnd {
			continue
		}

		wg.Add(1)
		go func(workerIdx, loStart, loEnd int) {
			defer wg.Done()
			var matches []Match

			for li := loStart; li < loEnd; li++ {
				lineText := lineTexts[li]
				offset := lineOffsets[li]

				// Skip empty lines — no pattern can match an empty string.
				if len(lineText) == 0 {
					continue
				}

				// Lowercase the line once for keyword checking.
				lineLower := strings.ToLower(lineText)

				// Run keyword patterns whose keywords appear on this line.
				for _, p := range keywordPatterns {
					keywordMatch := false
					for _, kw := range p.Keywords {
						if strings.Contains(lineLower, kw) {
							keywordMatch = true
							break
						}
					}
					if !keywordMatch {
						continue
					}
					indices := p.Compiled.FindAllStringIndex(lineText, -1)
					for _, idx := range indices {
						value := lineText[idx[0]:idx[1]]
						if len(value) > 200 {
							value = value[:200] + "..."
						}
						matches = append(matches, Match{
							Category:   p.Name,
							Severity:   p.Severity,
							Confidence: p.Confidence,
							Value:      value,
							Index:      idx[0] + offset,
							End:        idx[1] + offset,
						})
					}
				}

				// Run always-run patterns with required chars pre-filter.
				// Only run if the line contains ALL required chars.
				// Always-run patterns (no keywords) are handled separately
				// on the full text for efficiency — see below.
			}

			results[workerIdx] = matches
		}(w, batchStart, batchEnd)
	}
	wg.Wait()

	// Merge results from line-by-line keyword scanning.
	var all []Match
	for _, r := range results {
		all = append(all, r...)
	}

	// Run always-run patterns (no keywords) on the full text in parallel.
	// These are mostly simple PII patterns (SSN, phone, credit card, etc.)
	// that are fast on full text and have no keyword to pre-filter by.
	if len(alwaysRunPatterns) > 0 {
		arResults := make([][]Match, len(alwaysRunPatterns))
		var arWG sync.WaitGroup
		for i, p := range alwaysRunPatterns {
			arWG.Add(1)
			go func(idx int, pat compiledPattern) {
				defer arWG.Done()
				indices := pat.Compiled.FindAllStringIndex(text, -1)
				var matches []Match
				for _, idx2 := range indices {
					value := text[idx2[0]:idx2[1]]
					if len(value) > 200 {
						value = value[:200] + "..."
					}
					matches = append(matches, Match{
						Category:   pat.Name,
						Severity:   pat.Severity,
						Confidence: pat.Confidence,
						Value:      value,
						Index:      idx2[0],
						End:        idx2[1],
					})
				}
				arResults[idx] = matches
			}(i, p)
		}
		arWG.Wait()
		for _, r := range arResults {
			all = append(all, r...)
		}
	}

	// Sort all matches by index.
	sort.Slice(all, func(i, j int) bool {
		return all[i].Index < all[j].Index
	})

	return all
}

// DetectAll scans text with all pattern categories and returns combined results.
//
// For content larger than detectAllThreshold, categories are scanned
// concurrently for performance (up to 10x speedup on multi-core machines).
// For smaller content, categories are scanned sequentially to avoid
// goroutine overhead.
func DetectAll(text string) []Match {
	return DetectAllWithLanguage(text, LangAny)
}

// DetectAllWithLanguage scans text with all pattern categories, filtering
// patterns by language. Patterns without language restrictions always run.
func DetectAllWithLanguage(text string, lang Language) []Match {
	if len(text) == 0 {
		return nil
	}

	// For large text, use line-by-line scanning with keyword pre-filtering.
	// All 268 patterns are single-line (no (?s) dotall, no \n), so this is
	// a lossless optimization that dramatically reduces regex calls.
	if len(text) >= lineScanThreshold {
		return detectAllByLines(text, lang)
	}

	// Snapshot custom patterns under lock.
	customMu.RLock()
	customSnapshot := customPatterns
	customMu.RUnlock()

	// Pre-define all category scan functions with language filtering.
	scanners := []func() []Match{
		func() []Match { return detectWithPatternsFiltered(text, CompiledSecretPatterns, "secrets", lang) },
		func() []Match { return detectWithPatternsFiltered(text, CompiledXSSPatterns, "xss", lang) },
		func() []Match {
			return detectWithPatternsFiltered(text, CompiledPIIUSCorePatterns, "pii-us-core", lang)
		},
		func() []Match {
			return detectWithPatternsFiltered(text, CompiledPIIUSExtendedPatterns, "pii-us-extended", lang)
		},
		func() []Match {
			return detectWithPatternsFiltered(text, CompiledPIIFinancialPatterns, "pii-financial", lang)
		},
		func() []Match {
			return detectWithPatternsFiltered(text, CompiledPIIInternationalPatterns, "pii-international", lang)
		},
		func() []Match {
			return detectWithPatternsFiltered(text, CompiledCompliancePatterns, "compliance", lang)
		},
		func() []Match {
			return detectWithPatternsFiltered(text, CompiledDangerousFunctionPatterns, "dangerous-function", lang)
		},
		func() []Match {
			return detectWithPatternsFiltered(text, CompiledOTProtocolPatterns, "ot-protocols", lang)
		},
		func() []Match {
			return detectWithPatternsFiltered(text, CompiledRAGPatterns, "rag", lang)
		},
		func() []Match {
			return detectWithPatternsFiltered(text, CompiledPromptLeakagePatterns, "prompt-leakage", lang)
		},
	}
	if len(customSnapshot) > 0 {
		scanners = append(scanners, func() []Match {
			return detectWithPatternsFiltered(text, customSnapshot, "custom", lang)
		})
	}

	var all []Match

	if len(text) < detectAllThreshold {
		// Sequential scan for small content.
		for _, scan := range scanners {
			all = append(all, scan()...)
		}
	} else {
		// Concurrent scan for large content.
		results := make([][]Match, len(scanners))
		var wg sync.WaitGroup

		for i, scan := range scanners {
			wg.Add(1)
			go func(idx int, fn func() []Match) {
				defer wg.Done()
				results[idx] = fn()
			}(i, scan)
		}
		wg.Wait()

		for _, r := range results {
			all = append(all, r...)
		}
	}

	// Sort all matches by index
	sort.Slice(all, func(i, j int) bool {
		return all[i].Index < all[j].Index
	})

	return all
}

// DetectAllWithResults scans text with all pattern categories and returns
// per-category DetectionResult structs plus the combined match list.
func DetectAllWithResults(text string) ([]Match, []DetectionResult) {
	categories := []struct {
		patterns []compiledPattern
		category Category
	}{
		{CompiledSecretPatterns, CategorySecrets},
		{CompiledXSSPatterns, CategoryXSS},
		{CompiledPIIUSCorePatterns, CategoryPIIUSCore},
		{CompiledPIIUSExtendedPatterns, CategoryPIIUSExtended},
		{CompiledPIIFinancialPatterns, CategoryPIIFinancial},
		{CompiledPIIInternationalPatterns, CategoryPIIInternational},
		{CompiledCompliancePatterns, CategoryCompliance},
		{CompiledDangerousFunctionPatterns, CategoryDangerousFunction},
		{CompiledOTProtocolPatterns, CategoryOT},
		{CompiledRAGPatterns, CategoryRAG},
		{CompiledPromptLeakagePatterns, CategoryPromptLeakage},
	}

	results := make([]DetectionResult, len(categories))

	if len(text) == 0 {
		for i, cat := range categories {
			results[i] = DetectionResult{
				Category:     cat.category,
				Matches:      nil,
				PatternCount: len(cat.patterns),
				ElapsedNS:    0,
			}
		}
		return nil, results
	}

	var wg sync.WaitGroup
	for i, cat := range categories {
		wg.Add(1)
		go func(idx int, patterns []compiledPattern, category Category) {
			defer wg.Done()
			results[idx] = detectWithResult(text, patterns, category)
		}(i, cat.patterns, cat.category)
	}
	wg.Wait()

	var all []Match
	for _, r := range results {
		all = append(all, r.Matches...)
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].Index < all[j].Index
	})

	return all, results
}

// detectWithResult runs detection and returns a DetectionResult.
func detectWithResult(text string, patterns []compiledPattern, category Category) DetectionResult {
	start := time.Now()
	matches := detectWithPatterns(text, patterns, string(category))
	return DetectionResult{
		Category:     category,
		Matches:      matches,
		PatternCount: len(patterns),
		ElapsedNS:    time.Since(start).Nanoseconds(),
	}
}

// ---------------------------------------------------------------------
// Language detection from file extension
// ---------------------------------------------------------------------

// extensionLanguages maps file extensions to languages.
var extensionLanguages = map[string]Language{
	".py":   LangPython,
	".pyw":  LangPython,
	".js":   LangJS,
	".mjs":  LangJS,
	".cjs":  LangJS,
	".jsx":  LangJS,
	".ts":   LangTS,
	".tsx":  LangTS,
	".go":   LangGo,
	".java": LangJava,
	".c":    LangC,
	".h":    LangC,
	".cpp":  LangCPP,
	".cc":   LangCPP,
	".cxx":  LangCPP,
	".hpp":  LangCPP,
	".hxx":  LangCPP,
	".rb":   LangRuby,
	".php":  LangPHP,
	".sh":   LangShell,
	".bash": LangShell,
	".zsh":  LangShell,
	".yaml": LangYAML,
	".yml":  LangYAML,
	".json": LangJSON,
	".xml":  LangXML,
	".html": LangHTML,
	".htm":  LangHTML,
	".sql":  LangSQL,
}

// LanguageFromExtension returns the Language for a file extension.
// Returns LangGeneric for unknown extensions.
func LanguageFromExtension(ext string) Language {
	if lang, ok := extensionLanguages[strings.ToLower(ext)]; ok {
		return lang
	}
	return LangGeneric
}

// LanguageFromPath returns the Language for a file path based on its extension.
func LanguageFromPath(path string) Language {
	dot := strings.LastIndex(path, ".")
	if dot < 0 {
		return LangGeneric
	}
	return LanguageFromExtension(path[dot:])
}

// ---------------------------------------------------------------------
// Custom pattern registration (runtime extension)
// ---------------------------------------------------------------------

// customMu protects customPatterns for concurrent access.
var customMu sync.RWMutex

// customPatterns holds patterns registered at runtime via RegisterCustomPatterns.
var customPatterns []compiledPattern

// RegisterCustomPatterns compiles and registers custom pattern definitions.
// These patterns are included in all subsequent DetectAll calls.
// Returns an error if any pattern has an invalid regex.
func RegisterCustomPatterns(defs []PatternDef) error {
	customMu.Lock()
	defer customMu.Unlock()
	for _, def := range defs {
		re, err := regexp.Compile(def.Regex)
		if err != nil {
			return fmt.Errorf("invalid regex for custom pattern %s: %w", def.Name, err)
		}
		customPatterns = append(customPatterns, compiledPattern{
			Name:        def.Name,
			Severity:    def.Severity,
			Confidence:  1.0,
			Compiled:    re,
			Description: def.Description,
			Languages:   def.Languages,
		})
	}
	return nil
}

// DetectCustomPatterns scans text using runtime-registered custom patterns.
func DetectCustomPatterns(text string) []Match {
	customMu.RLock()
	snapshot := customPatterns
	customMu.RUnlock()
	if len(snapshot) == 0 {
		return nil
	}
	return detectWithPatterns(text, snapshot, "custom")
}

// ResetCustomPatterns clears all registered custom patterns.
// Primarily used in tests.
func ResetCustomPatterns() {
	customMu.Lock()
	defer customMu.Unlock()
	customPatterns = nil
}

// AllPatternDefs returns all built-in pattern definitions from all
// categories. This is used to compute a pattern set hash for cache
// invalidation — any change to any pattern (add, remove, modify) will
// produce a different hash, ensuring cached results are invalidated.
func AllPatternDefs() []PatternDef {
	return concatPatternDefs(
		SecretsPatterns,
		XSSPatterns,
		PIIUSCorePatterns,
		PIIUSExtendedPatterns,
		PIIFinancialPatterns,
		PIIInternationalPatterns,
		CompliancePatterns,
		DangerousFunctionPatterns,
		OTProtocolPatterns,
		RAGPatterns,
		PromptLeakageResponsePatterns,
	)
}

func concatPatternDefs(slices ...[]PatternDef) []PatternDef {
	total := 0
	for _, s := range slices {
		total += len(s)
	}
	result := make([]PatternDef, 0, total)
	for _, s := range slices {
		result = append(result, s...)
	}
	return result
}
