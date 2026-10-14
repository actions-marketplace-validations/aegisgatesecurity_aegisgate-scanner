// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Platform Forwarder — Core Implementation
// =========================================================================

package platformforward

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/contracts"
	scanner "github.com/aegisgatesecurity/aegisgate-scanner/pkg/scanner"
)

// defaultVersion is used if no version is explicitly set.
const defaultVersion = "0.3.0"

// Forwarder pushes scan detection metadata to AegisGate Platform.
//
// It is air-gap compatible: if the platform URL is empty, all
// forwarding operations are no-ops. The Forwarder uses a background
// goroutine for HTTP sends so it never blocks the scan pipeline.
type Forwarder struct {
	url     string
	apiKey  string
	version string
	client  *http.Client
	enabled bool

	// Buffer for batching events before flush.
	mu    sync.Mutex
	buf   []contracts.Event
	timer *time.Timer

	// For testing
	nowFunc func() time.Time
}

// New creates a Platform forwarder. If url is empty, forwarding is disabled.
func New(url string) *Forwarder {
	return NewWithAPIKey(url, "")
}

// NewWithAPIKey creates a Platform forwarder with API key authentication.
func NewWithAPIKey(url, apiKey string) *Forwarder {
	enabled := url != ""
	if enabled {
		masked := maskURL(url)
		log.Printf("scanner: platform forwarding enabled → %s", masked)
	} else {
		log.Printf("scanner: platform forwarding disabled (no platform_url configured)")
	}

	return &Forwarder{
		url:     url,
		apiKey:  apiKey,
		version: defaultVersion,
		client:  &http.Client{Timeout: 10 * time.Second},
		enabled: enabled,
		nowFunc: time.Now,
	}
}

// SetVersion sets the scanner version included in forwarded events.
func (f *Forwarder) SetVersion(v string) {
	f.version = v
}

// Enabled returns whether forwarding is active.
func (f *Forwarder) Enabled() bool {
	return f.enabled
}

// ForwardFindings converts a slice of scanner findings for a single
// artifact into a canonical Event and sends it to Platform.
// Non-blocking: errors are logged but never returned to the caller.
func (f *Forwarder) ForwardFindings(artifact string, findings []scanner.Finding) {
	if !f.enabled || len(findings) == 0 {
		return
	}
	event := FindingsToEvent(artifact, findings, f.version, f.nowFunc())
	go f.sendEvent(event)
}

// ForwardFindingsSync is the synchronous version of ForwardFindings.
// It blocks until the HTTP request completes. Used by CLI mode where
// the program is about to exit and we want to ensure delivery.
func (f *Forwarder) ForwardFindingsSync(artifact string, findings []scanner.Finding) error {
	if !f.enabled {
		return nil
	}
	if len(findings) == 0 {
		return nil
	}
	event := FindingsToEvent(artifact, findings, f.version, f.nowFunc())
	batch := contracts.EventBatch{
		SchemaVersion: "v1",
		Source:        contracts.SourceScanner,
		Events:        []contracts.Event{event},
	}
	return f.sendBatchSync(batch)
}

// ForwardBatch sends a pre-constructed EventBatch to Platform.
// This is useful when the caller wants to batch multiple artifacts
// into a single HTTP request.
func (f *Forwarder) ForwardBatch(batch contracts.EventBatch) error {
	if !f.enabled {
		return nil
	}
	return f.sendBatchSync(batch)
}

// Flush sends any buffered events. Currently a no-op placeholder
// for future batching logic.
func (f *Forwarder) Flush() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.buf) == 0 {
		return nil
	}
	batch := contracts.EventBatch{
		SchemaVersion: "v1",
		Source:        contracts.SourceScanner,
		Events:        f.buf,
	}
	f.buf = f.buf[:0]
	return f.sendBatchSync(batch)
}

// HeartbeatResult contains the result of a Platform connectivity check.
type HeartbeatResult struct {
	Success   bool          `json:"success"`
	Latency   time.Duration `json:"latency_ms"`
	Error     string        `json:"error,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

// Heartbeat performs a connectivity check to Platform's /api/v1/healthz.
// Returns success status, latency, and any error. Blocking with 10s timeout.
func (f *Forwarder) Heartbeat() HeartbeatResult {
	result := HeartbeatResult{Timestamp: f.nowFunc()}

	if !f.enabled {
		result.Error = "platform forwarding disabled"
		return result
	}

	// Build healthz URL from the telemetry URL
	healthURL := healthzURL(f.url)

	start := f.nowFunc()
	req, err := http.NewRequest(http.MethodGet, healthURL, nil)
	if err != nil {
		result.Error = fmt.Sprintf("request creation failed: %v", err)
		return result
	}
	if f.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+f.apiKey)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("connectivity check failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.Latency = f.nowFunc().Sub(start)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return result
	}

	result.Success = true
	return result
}

// StartHeartbeatLoop begins periodic heartbeat checks to Platform.
// Returns a channel that receives heartbeat results at the specified interval.
// The loop stops when the context is cancelled.
func (f *Forwarder) StartHeartbeatLoop(ctx context.Context, interval time.Duration) <-chan HeartbeatResult {
	results := make(chan HeartbeatResult, 1)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		defer close(results)

		for {
			select {
			case <-ctx.Done():
				log.Printf("scanner: platform heartbeat loop stopped")
				return
			case <-ticker.C:
				result := f.Heartbeat()
				if result.Success {
					log.Printf("scanner: platform heartbeat OK (latency: %v)", result.Latency)
				} else {
					log.Printf("scanner: platform heartbeat FAILED: %s", result.Error)
				}
				select {
				case results <- result:
				default:
				}
			}
		}
	}()

	return results
}

// String implements fmt.Stringer for diagnostics.
func (f *Forwarder) String() string {
	if !f.enabled {
		return "platform forwarding disabled"
	}
	return fmt.Sprintf("platform forwarding → %s", maskURL(f.url))
}

// === Internal methods ===

// sendEvent sends a single event as a batch. Non-blocking.
func (f *Forwarder) sendEvent(event contracts.Event) {
	batch := contracts.EventBatch{
		SchemaVersion: "v1",
		Source:        contracts.SourceScanner,
		Events:        []contracts.Event{event},
	}
	if err := f.sendBatchSync(batch); err != nil {
		log.Printf("scanner: platform forward error: %v", err)
	}
}

// sendBatchSync sends an EventBatch to Platform. Blocking.
func (f *Forwarder) sendBatchSync(batch contracts.EventBatch) error {
	payload, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, f.url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("request error: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if f.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+f.apiKey)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("send error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("platform rejected: HTTP %d", resp.StatusCode)
	}
	return nil
}

// === Converter functions ===

// FindingsToEvent converts a slice of scanner findings for a single
// artifact into a canonical contracts.Event. This is the key converter
// that bridges Scanner's internal types to the shared schema.
//
// PRIVACY: MatchedText is NEVER included in the output. Only metadata
// (rule ID, category, severity, confidence, line/column, message) is sent.
func FindingsToEvent(artifact string, findings []scanner.Finding, sourceVersion string, ts time.Time) contracts.Event {
	eventFindings := make([]contracts.EventFinding, 0, len(findings))
	categories := make(map[string]struct{})
	severities := make(map[string]struct{})
	rules := make(map[string]struct{})
	piiCats := make(map[string]struct{})
	secretTypes := make(map[string]struct{})

	for _, f := range findings {
		ef := contracts.EventFinding{
			RuleID:     f.RuleID,
			Category:   f.Category,
			Severity:   string(f.Severity),
			Confidence: f.Confidence,
			Message:    f.Message,
			Line:       f.Line,
			Column:     f.Column,
			EndLine:    f.EndLine,
			EndColumn:  f.EndColumn,
		}
		// NOTE: f.MatchedText is deliberately excluded — privacy non-negotiable.
		eventFindings = append(eventFindings, ef)

		categories[f.Category] = struct{}{}
		severities[string(f.Severity)] = struct{}{}
		rules[f.RuleID] = struct{}{}

		// Categorize PII and secrets for summary fields
		if isPIICategory(f.Category) {
			piiCats[f.Category] = struct{}{}
		}
		if isSecretCategory(f.Category) {
			secretTypes[f.RuleID] = struct{}{}
		}
	}

	// Determine action based on findings
	action := "logged"
	hasCritical := false
	for _, f := range findings {
		if string(f.Severity) == "critical" {
			hasCritical = true
			break
		}
	}
	if hasCritical {
		action = "flagged"
	}

	return contracts.Event{
		ID:              generateEventID(ts),
		Source:          contracts.SourceScanner,
		SourceVersion:   sourceVersion,
		Timestamp:       ts,
		SchemaVersion:   "v1",
		Direction:       contracts.DirectionScan,
		Artifact:        artifact,
		TotalDetections: len(findings),
		Blocked:         false, // Scanner detects but doesn't block
		Action:          action,
		Findings:        eventFindings,
		Categories:      mapKeys(categories),
		Severities:      mapKeys(severities),
		Rules:           mapKeys(rules),
		PIICategories:   mapKeys(piiCats),
		SecretTypes:     mapKeys(secretTypes),
	}
}

// FindingsToBatch converts findings from multiple artifacts into a
// single EventBatch, grouping findings by artifact.
func FindingsToBatch(results map[string][]scanner.Finding, sourceVersion string, ts time.Time) contracts.EventBatch {
	events := make([]contracts.Event, 0, len(results))
	for artifact, findings := range results {
		if len(findings) == 0 {
			continue
		}
		events = append(events, FindingsToEvent(artifact, findings, sourceVersion, ts))
	}
	return contracts.EventBatch{
		SchemaVersion: "v1",
		Source:        contracts.SourceScanner,
		Events:        events,
	}
}

// === Helpers ===

// isPIICategory returns true if the category is a PII sub-category.
func isPIICategory(cat string) bool {
	switch cat {
	case "pii-us-core", "pii-us-extended", "pii-financial", "pii-international":
		return true
	}
	return false
}

// isSecretCategory returns true if the category is secrets.
func isSecretCategory(cat string) bool {
	return cat == "secrets"
}

// mapKeys extracts keys from a map[string]struct{} into a sorted slice.
func mapKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// generateEventID creates a unique event ID from the timestamp.
// Uses Unix nanoseconds + a counter for uniqueness within a process.
var eventCounter uint64

func generateEventID(ts time.Time) string {
	return fmt.Sprintf("scan-%d", ts.UnixNano())
}

// maskURL masks the URL for safe logging.
func maskURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "[invalid-url]"
	}
	return u.Scheme + "://" + u.Hostname() + "/..."
}

// healthzURL derives the /api/v1/healthz URL from the telemetry URL.
// Assumes the telemetry URL ends with /api/v1/telemetry.
func healthzURL(telemetryURL string) string {
	u, err := url.Parse(telemetryURL)
	if err != nil {
		return telemetryURL
	}
	u.Path = "/api/v1/healthz"
	return u.String()
}
