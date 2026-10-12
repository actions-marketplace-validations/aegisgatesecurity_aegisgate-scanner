// SPDX-License-Identifier: Apache-2.0
// Provenance: github.com/aegisgatesecurity/aegisgate-platform/pkg/response/detectors (v4.0.0)
// =========================================================================
// AegisGate Platform - Detector Engine
// =========================================================================
//
// Shared detection engine that compiles PatternDef slices into regexp.Regexp
// and scans text for matches. This is the core runtime that all 7 detector
// packages use.
// =========================================================================

package detectors

import (
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"
)

// compiledPattern holds a pre-compiled regex pattern with its metadata.
type compiledPattern struct {
	Name        string
	Severity    Severity
	Confidence  float64
	Compiled    *regexp.Regexp
	Description string
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
		}
	}
	return patterns
}

// detectWithPatterns scans text using pre-compiled patterns and returns matches.
func detectWithPatterns(text string, patterns []compiledPattern, category string) []Match {
	if len(text) == 0 {
		return nil
	}

	start := time.Now()
	var matches []Match

	for _, p := range patterns {
		indices := p.Compiled.FindAllStringIndex(text, -1)
		for _, idx := range indices {
			value := text[idx[0]:idx[1]]
			// Truncate long matches (mirrors Lens behavior)
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

	// Sort by index (mirrors Lens behavior)
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Index < matches[j].Index
	})

	_ = time.Since(start) // available for future metrics

	return matches
}

// detectAllThreshold is the minimum content size (bytes) for concurrent
// category scanning. Below this threshold, goroutine overhead exceeds the
// benefit of parallelism, so categories are scanned sequentially.
const detectAllThreshold = 8192 // 8KB

// DetectAll scans text with all pattern categories and returns combined results.
//
// For content larger than detectAllThreshold, categories are scanned
// concurrently for performance (up to 10x speedup on multi-core machines).
// For smaller content, categories are scanned sequentially to avoid
// goroutine overhead.
func DetectAll(text string) []Match {
	if len(text) == 0 {
		return nil
	}

	// Snapshot custom patterns under lock to avoid race with RegisterCustomPatterns.
	customMu.RLock()
	customSnapshot := customPatterns
	customMu.RUnlock()

	// Pre-define all category scan functions.
	scanners := []func() []Match{
		func() []Match { return detectWithPatterns(text, CompiledSecretPatterns, "secrets") },
		func() []Match { return detectWithPatterns(text, CompiledXSSPatterns, "xss") },
		func() []Match { return detectWithPatterns(text, CompiledPIIUSCorePatterns, "pii-us-core") },
		func() []Match { return detectWithPatterns(text, CompiledPIIUSExtendedPatterns, "pii-us-extended") },
		func() []Match { return detectWithPatterns(text, CompiledPIIFinancialPatterns, "pii-financial") },
		func() []Match { return detectWithPatterns(text, CompiledPIIInternationalPatterns, "pii-international") },
		func() []Match { return detectWithPatterns(text, CompiledCompliancePatterns, "compliance") },
		func() []Match {
			return detectWithPatterns(text, CompiledDangerousFunctionPatterns, "dangerous-function")
		},
		func() []Match { return detectWithPatterns(text, CompiledOTProtocolPatterns, "ot-protocols") },
	}
	if len(customSnapshot) > 0 {
		scanners = append(scanners, func() []Match {
			return detectWithPatterns(text, customSnapshot, "custom")
		})
	}

	var all []Match

	if len(text) < detectAllThreshold {
		// Sequential scan for small content (avoids goroutine overhead).
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
	}

	results := make([]DetectionResult, len(categories))

	if len(text) == 0 {
		// Return empty results for each category (preserves category count).
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

	// Build combined match list from results.
	var all []Match
	for _, r := range results {
		all = append(all, r.Matches...)
	}

	// Sort all matches by index
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
