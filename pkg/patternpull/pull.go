// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner - Pattern Pull Implementation
// =========================================================================

package patternpull

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/detectors"
)

// ---------------------------------------------------------------------
// JSON response types (local definitions, not importing Platform contracts)
// ---------------------------------------------------------------------

// patternSetResponse mirrors contracts.PatternSetResponse from the Platform.
type patternSetResponse struct {
	APIVersion string     `json:"api_version"`
	PatternSet patternSet `json:"pattern_set"`
	UpdatedAt  string     `json:"updated_at"`
}

// patternSet mirrors contracts.PatternSet from the Platform.
type patternSet struct {
	Version     string         `json:"version"`
	Source      string         `json:"source"`
	GeneratedAt string         `json:"generated_at"`
	Hash        string         `json:"hash"`
	Patterns    []patternEntry `json:"patterns"`
}

// patternEntry mirrors contracts.Pattern from the Platform.
type patternEntry struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Regex       string   `json:"regex"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Languages   []string `json:"languages,omitempty"`
	Keywords    []string `json:"keywords,omitempty"`
	Confidence  string   `json:"confidence,omitempty"`
}

// ---------------------------------------------------------------------
// PullResult
// ---------------------------------------------------------------------

// PullResult holds the result of a pattern pull operation.
type PullResult struct {
	// Patterns is the converted slice of detectors.PatternDef ready for
	// registration.
	Patterns []detectors.PatternDef

	// RawCount is the number of patterns returned by the Platform before
	// filtering (e.g., skipping empty regex).
	RawCount int

	// UpdatedAt is the timestamp from the Platform response.
	UpdatedAt string

	// Hash is the pattern set hash from the Platform.
	Hash string

	// FromCache is true if the Platform returned 304 Not Modified,
	// meaning no patterns were transferred.
	FromCache bool
}

// ---------------------------------------------------------------------
// Puller
// ---------------------------------------------------------------------

// Puller fetches canonical patterns from the Platform and optionally
// registers them as custom patterns in the Scanner's detector engine.
type Puller struct {
	url         string // Platform base URL (e.g., "https://platform.example.com:9091")
	apiKey      string // Bearer token
	client      *http.Client
	enabled     bool   // true if url is non-empty
	lastUpdated string // Last-Modified value from last successful pull
	nowFunc     func() time.Time
	version     string // Scanner version for User-Agent
}

// defaultHTTPClient returns a reasonable HTTP client for pulling patterns.
func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
	}
}

// New creates a Puller for the given Platform base URL.
// The puller is enabled only if the URL is non-empty.
func New(url string) *Puller {
	return &Puller{
		url:     strings.TrimRight(url, "/"),
		enabled: url != "",
		client:  defaultHTTPClient(),
		nowFunc: time.Now,
		version: "aegisgate-scanner",
	}
}

// NewWithAPIKey creates a Puller with an API key for Bearer authentication.
// The puller is enabled only if the URL is non-empty.
func NewWithAPIKey(url, apiKey string) *Puller {
	p := New(url)
	p.apiKey = apiKey
	return p
}

// IsEnabled returns true if the puller has a non-empty Platform URL.
func (p *Puller) IsEnabled() bool {
	return p.enabled
}

// Pull fetches patterns from the Platform's /api/v1/patterns/latest endpoint.
// It uses the If-Modified-Since header for bandwidth efficiency.
// Returns a PullResult with converted patterns, or nil if the Platform
// responds with 304 Not Modified (FromCache would be set in that case).
func (p *Puller) Pull() (*PullResult, error) {
	if !p.enabled {
		return nil, fmt.Errorf("patternpull: puller is disabled (empty platform URL)")
	}

	endpoint := p.url + "/api/v1/patterns/latest"

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("patternpull: failed to create request: %w", err)
	}

	// User-Agent for identification.
	req.Header.Set("User-Agent", p.version)

	// API key authentication.
	if p.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}

	// If-Modified-Since for bandwidth efficiency.
	if p.lastUpdated != "" {
		req.Header.Set("If-Modified-Since", p.lastUpdated)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("patternpull: request failed: %w", err)
	}
	defer resp.Body.Close()

	// 304 Not Modified — patterns haven't changed.
	if resp.StatusCode == http.StatusNotModified {
		return &PullResult{
			FromCache: true,
		}, nil
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("patternpull: authentication failed (401 Unauthorized)")
	}

	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("patternpull: server error (HTTP %d)", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("patternpull: unexpected status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("patternpull: failed to read response body: %w", err)
	}

	var psr patternSetResponse
	if err := json.Unmarshal(body, &psr); err != nil {
		return nil, fmt.Errorf("patternpull: failed to parse JSON response: %w", err)
	}

	// Track Last-Modified for future If-Modified-Since requests.
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		p.lastUpdated = lm
	} else if psr.UpdatedAt != "" {
		p.lastUpdated = psr.UpdatedAt
	}

	defs := contractsToPatternDefs(psr.PatternSet.Patterns)

	return &PullResult{
		Patterns:  defs,
		RawCount:  len(psr.PatternSet.Patterns),
		UpdatedAt: psr.UpdatedAt,
		Hash:      psr.PatternSet.Hash,
		FromCache: false,
	}, nil
}

// PullAndRegister is a convenience method that pulls patterns from the
// Platform and registers them as custom patterns via
// detectors.RegisterCustomPatterns. Returns the number of patterns
// registered.
func (p *Puller) PullAndRegister() (int, error) {
	result, err := p.Pull()
	if err != nil {
		return 0, err
	}

	if result == nil || result.FromCache {
		// 304 Not Modified or nil result — nothing new to register.
		return 0, nil
	}

	if len(result.Patterns) == 0 {
		return 0, nil
	}

	if err := detectors.RegisterCustomPatterns(result.Patterns); err != nil {
		return 0, fmt.Errorf("patternpull: failed to register patterns: %w", err)
	}

	return len(result.Patterns), nil
}

// StartPullLoop runs a background loop that pulls patterns at regular
// intervals. It blocks until the context is cancelled.
func (p *Puller) StartPullLoop(ctx context.Context, interval time.Duration) {
	// Do an initial pull immediately.
	_, _ = p.PullAndRegister()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = p.PullAndRegister()
		}
	}
}

// Healthz checks the Platform's health endpoint.
// Returns nil if the Platform is healthy, an error otherwise.
func (p *Puller) Healthz() error {
	if !p.enabled {
		return fmt.Errorf("patternpull: puller is disabled (empty platform URL)")
	}

	endpoint := p.url + "/healthz"

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("patternpull: failed to create healthz request: %w", err)
	}

	req.Header.Set("User-Agent", p.version)

	if p.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("patternpull: healthz request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("patternpull: healthz returned HTTP %d", resp.StatusCode)
	}

	return nil
}

// ---------------------------------------------------------------------
// Converter
// ---------------------------------------------------------------------

// contractsToPatternDefs converts canonical Platform patterns (from JSON)
// to the Scanner's detectors.PatternDef. Patterns with empty regex or
// empty name are skipped.
func contractsToPatternDefs(patterns []patternEntry) []detectors.PatternDef {
	defs := make([]detectors.PatternDef, 0, len(patterns))
	for _, p := range patterns {
		// Skip patterns with empty regex or empty name.
		if p.Regex == "" || p.Name == "" {
			continue
		}

		def := detectors.PatternDef{
			Name:        p.Name,
			Severity:    mapSeverity(p.Severity),
			Regex:       p.Regex,
			Description: p.Description,
			Category:    detectors.Category(p.Category),
			Languages:   mapLanguages(p.Languages),
		}

		defs = append(defs, def)
	}
	return defs
}

// mapSeverity maps a canonical severity string to detectors.Severity.
// Unknown severities default to SeverityMedium.
func mapSeverity(s string) detectors.Severity {
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
		return detectors.SeverityMedium
	}
}

// mapLanguages maps a slice of language strings to detectors.Language.
func mapLanguages(langs []string) []detectors.Language {
	result := make([]detectors.Language, 0, len(langs))
	for _, l := range langs {
		result = append(result, detectors.Language(l))
	}
	return result
}
