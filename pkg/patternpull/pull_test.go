// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner - Pattern Pull Tests
// =========================================================================

package patternpull

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/detectors"
)

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// validPatternSetJSON returns a JSON-encoded pattern set response for testing.
func validPatternSetJSON() string {
	resp := patternSetResponse{
		APIVersion: "v1",
		PatternSet: patternSet{
			Version:     "v1",
			Source:      "platform",
			GeneratedAt: "2026-10-14T12:00:00Z",
			Hash:        "count:3",
			Patterns: []patternEntry{
				{
					ID:          "test-1",
					Name:        "test_aws_key",
					Regex:       "AKIA[0-9A-Z]{16}",
					Severity:    "critical",
					Category:    "secrets",
					Description: "Test AWS access key",
					Languages:   []string{"python", "javascript"},
					Keywords:    []string{"akia"},
					Confidence:  "high",
				},
				{
					ID:          "test-2",
					Name:        "test_ssn",
					Regex:       `\d{3}-\d{2}-\d{4}`,
					Severity:    "high",
					Category:    "pii-us-core",
					Description: "Test SSN pattern",
					Languages:   []string{},
				},
				{
					ID:          "test-3",
					Name:        "test_empty_regex",
					Regex:       "",
					Severity:    "low",
					Category:    "secrets",
					Description: "Should be skipped",
				},
			},
		},
		UpdatedAt: "2026-10-14T12:00:00Z",
	}
	b, _ := json.Marshal(resp)
	return string(b)
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

func TestNew_EmptyURL(t *testing.T) {
	p := New("")
	if p.IsEnabled() {
		t.Fatal("expected puller with empty URL to be disabled")
	}
	if p.url != "" {
		t.Fatalf("expected empty url, got %q", p.url)
	}
}

func TestNew_NonEmptyURL(t *testing.T) {
	p := New("https://example.com:9091")
	if !p.IsEnabled() {
		t.Fatal("expected puller with non-empty URL to be enabled")
	}
	if p.url != "https://example.com:9091" {
		t.Fatalf("expected url to be 'https://example.com:9091', got %q", p.url)
	}
}

func TestNew_TrimsTrailingSlash(t *testing.T) {
	p := New("https://example.com:9091/")
	if p.url != "https://example.com:9091" {
		t.Fatalf("expected trailing slash trimmed, got %q", p.url)
	}
}

func TestNewWithAPIKey(t *testing.T) {
	p := NewWithAPIKey("https://example.com", "secret-key-123")
	if !p.IsEnabled() {
		t.Fatal("expected puller with URL and API key to be enabled")
	}
	if p.apiKey != "secret-key-123" {
		t.Fatalf("expected apiKey 'secret-key-123', got %q", p.apiKey)
	}
}

func TestIsEnabled(t *testing.T) {
	disabled := New("")
	if disabled.IsEnabled() {
		t.Fatal("expected disabled puller")
	}

	enabled := New("https://example.com")
	if !enabled.IsEnabled() {
		t.Fatal("expected enabled puller")
	}
}

func TestPull_Disabled(t *testing.T) {
	p := New("")
	_, err := p.Pull()
	if err == nil {
		t.Fatal("expected error when pulling on disabled puller")
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected error about disabled puller, got: %v", err)
	}
}

func TestPull_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/patterns/latest" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Last-Modified", "Wed, 14 Oct 2026 12:00:00 GMT")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, validPatternSetJSON())
	}))
	defer srv.Close()

	p := New(srv.URL)
	result, err := p.Pull()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.FromCache {
		t.Fatal("expected FromCache=false on successful pull")
	}
	if result.RawCount != 3 {
		t.Fatalf("expected RawCount=3, got %d", result.RawCount)
	}
	// One pattern has empty regex → should be skipped → 2 patterns.
	if len(result.Patterns) != 2 {
		t.Fatalf("expected 2 patterns (1 skipped for empty regex), got %d", len(result.Patterns))
	}
	if result.Hash != "count:3" {
		t.Fatalf("expected hash 'count:3', got %q", result.Hash)
	}
	if result.UpdatedAt != "2026-10-14T12:00:00Z" {
		t.Fatalf("unexpected UpdatedAt: %q", result.UpdatedAt)
	}

	// Verify first pattern conversion.
	pat := result.Patterns[0]
	if pat.Name != "test_aws_key" {
		t.Fatalf("expected name 'test_aws_key', got %q", pat.Name)
	}
	if pat.Severity != detectors.SeverityCritical {
		t.Fatalf("expected severity critical, got %s", pat.Severity)
	}
	if pat.Regex != "AKIA[0-9A-Z]{16}" {
		t.Fatalf("unexpected regex: %q", pat.Regex)
	}
	if len(pat.Languages) != 2 {
		t.Fatalf("expected 2 languages, got %d", len(pat.Languages))
	}
	if pat.Languages[0] != detectors.LangPython {
		t.Fatalf("expected first language 'python', got %s", pat.Languages[0])
	}
}

func TestPull_APIKeySent(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, validPatternSetJSON())
	}))
	defer srv.Close()

	p := NewWithAPIKey(srv.URL, "my-token")
	_, err := p.Pull()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "Bearer my-token" {
		t.Fatalf("expected Authorization 'Bearer my-token', got %q", gotAuth)
	}
}

func TestPull_NotModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-Modified-Since") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Last-Modified", "Wed, 14 Oct 2026 12:00:00 GMT")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, validPatternSetJSON())
	}))
	defer srv.Close()

	p := New(srv.URL)

	// First pull — gets full response.
	result1, err := p.Pull()
	if err != nil {
		t.Fatalf("first pull error: %v", err)
	}
	if result1.FromCache {
		t.Fatal("expected first pull FromCache=false")
	}

	// Second pull — should get 304.
	result2, err := p.Pull()
	if err != nil {
		t.Fatalf("second pull error: %v", err)
	}
	if result2 == nil {
		t.Fatal("expected non-nil result on 304")
	}
	if !result2.FromCache {
		t.Fatal("expected second pull FromCache=true")
	}
	if len(result2.Patterns) != 0 {
		t.Fatalf("expected 0 patterns on 304, got %d", len(result2.Patterns))
	}
}

func TestPull_AuthFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := New(srv.URL)
	_, err := p.Pull()
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if !strings.Contains(err.Error(), "401") && !strings.Contains(err.Error(), "authentication") {
		t.Fatalf("expected auth-related error, got: %v", err)
	}
}

func TestPull_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := New(srv.URL)
	_, err := p.Pull()
	if err == nil {
		t.Fatal("expected error on 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected server error, got: %v", err)
	}
}

func TestPullAndRegister(t *testing.T) {
	// Reset custom patterns to ensure clean state.
	detectors.ResetCustomPatterns()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, validPatternSetJSON())
	}))
	defer srv.Close()

	p := New(srv.URL)
	count, err := p.PullAndRegister()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 3 raw patterns, 1 skipped (empty regex) → 2 registered.
	if count != 2 {
		t.Fatalf("expected 2 patterns registered, got %d", count)
	}

	// Verify patterns are actually registered by detecting.
	matches := detectors.DetectCustomPatterns("AKIAABCDEFGHIJKLMNOP")
	if len(matches) == 0 {
		t.Fatal("expected custom pattern to detect AWS key")
	}

	// Clean up.
	detectors.ResetCustomPatterns()
}

func TestPullAndRegister_Disabled(t *testing.T) {
	detectors.ResetCustomPatterns()
	p := New("")
	count, err := p.PullAndRegister()
	if err == nil {
		t.Fatal("expected error on disabled puller")
	}
	if count != 0 {
		t.Fatalf("expected 0 count, got %d", count)
	}
	detectors.ResetCustomPatterns()
}

func TestPullAndRegister_NotModified(t *testing.T) {
	detectors.ResetCustomPatterns()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	p := New(srv.URL)
	count, err := p.PullAndRegister()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 patterns on 304, got %d", count)
	}

	detectors.ResetCustomPatterns()
}

func TestHealthz_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	p := New(srv.URL)
	if err := p.Healthz(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHealthz_Failure(t *testing.T) {
	// Use a port that's almost certainly not listening.
	p := New("http://127.0.0.1:1")
	err := p.Healthz()
	if err == nil {
		t.Fatal("expected error on connection failure")
	}
}

func TestHealthz_Disabled(t *testing.T) {
	p := New("")
	err := p.Healthz()
	if err == nil {
		t.Fatal("expected error on disabled puller healthz")
	}
}

func TestContractsToPatternDefs(t *testing.T) {
	patterns := []patternEntry{
		{
			Name:        "secret_token",
			Regex:       `token["\s:=]+[A-Za-z0-9]{32}`,
			Severity:    "high",
			Category:    "secrets",
			Description: "Detects token assignments",
			Languages:   []string{"python", "go"},
		},
		{
			Name:        "xss_reflected",
			Regex:       `document\.write\(`,
			Severity:    "medium",
			Category:    "xss",
			Description: "XSS via document.write",
		},
		{
			Name:        "unknown_severity",
			Regex:       `something`,
			Severity:    "weird",
			Category:    "custom-cat",
			Description: "Unknown severity should default to medium",
		},
	}

	defs := contractsToPatternDefs(patterns)
	if len(defs) != 3 {
		t.Fatalf("expected 3 defs, got %d", len(defs))
	}

	// Check first pattern.
	if defs[0].Name != "secret_token" {
		t.Fatalf("expected name 'secret_token', got %q", defs[0].Name)
	}
	if defs[0].Severity != detectors.SeverityHigh {
		t.Fatalf("expected severity high, got %s", defs[0].Severity)
	}
	if defs[0].Category != detectors.Category("secrets") {
		t.Fatalf("expected category 'secrets', got %s", defs[0].Category)
	}
	if len(defs[0].Languages) != 2 {
		t.Fatalf("expected 2 languages, got %d", len(defs[0].Languages))
	}

	// Check unknown severity defaults to medium.
	if defs[2].Severity != detectors.SeverityMedium {
		t.Fatalf("expected unknown severity to default to medium, got %s", defs[2].Severity)
	}
}

func TestContractsToPatternDefs_EmptyRegex(t *testing.T) {
	patterns := []patternEntry{
		{Name: "has_regex", Regex: `\d+`, Severity: "low"},
		{Name: "no_regex", Regex: "", Severity: "low"},
		{Name: "", Regex: `\d+`, Severity: "low"}, // empty name
	}

	defs := contractsToPatternDefs(patterns)
	if len(defs) != 1 {
		t.Fatalf("expected 1 def (2 skipped), got %d", len(defs))
	}
	if defs[0].Name != "has_regex" {
		t.Fatalf("expected name 'has_regex', got %q", defs[0].Name)
	}
}

func TestContractsToPatternDefs_Empty(t *testing.T) {
	defs := contractsToPatternDefs(nil)
	if len(defs) != 0 {
		t.Fatalf("expected 0 defs for nil input, got %d", len(defs))
	}
}

func TestStartPullLoop(t *testing.T) {
	detectors.ResetCustomPatterns()

	pullCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/patterns/latest" {
			pullCount++
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, validPatternSetJSON())
		}
	}))
	defer srv.Close()

	p := New(srv.URL)

	ctx, cancel := context.WithCancel(context.Background())

	// Run the loop in a goroutine with a short interval.
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	// This blocks until ctx is cancelled.
	p.StartPullLoop(ctx, 50*time.Millisecond)

	if pullCount < 1 {
		t.Fatalf("expected at least 1 pull, got %d", pullCount)
	}

	detectors.ResetCustomPatterns()
}

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected detectors.Severity
	}{
		{"critical", detectors.SeverityCritical},
		{"high", detectors.SeverityHigh},
		{"medium", detectors.SeverityMedium},
		{"low", detectors.SeverityLow},
		{"CRITICAL", detectors.SeverityCritical}, // case-insensitive
		{"unknown", detectors.SeverityMedium},    // default
		{"", detectors.SeverityMedium},           // default
	}

	for _, tc := range tests {
		got := mapSeverity(tc.input)
		if got != tc.expected {
			t.Errorf("mapSeverity(%q) = %s, want %s", tc.input, got, tc.expected)
		}
	}
}

func TestMapLanguages(t *testing.T) {
	langs := mapLanguages([]string{"python", "javascript", "go"})
	if len(langs) != 3 {
		t.Fatalf("expected 3 languages, got %d", len(langs))
	}
	if langs[0] != detectors.LangPython {
		t.Fatalf("expected python, got %s", langs[0])
	}
	if langs[1] != detectors.LangJS {
		t.Fatalf("expected javascript, got %s", langs[1])
	}
	if langs[2] != detectors.LangGo {
		t.Fatalf("expected go, got %s", langs[2])
	}

	// Empty input.
	empty := mapLanguages(nil)
	if len(empty) != 0 {
		t.Fatalf("expected 0 languages for nil input, got %d", len(empty))
	}
}
