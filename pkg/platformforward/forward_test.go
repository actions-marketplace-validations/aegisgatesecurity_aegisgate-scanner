// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Platform Forwarder — Tests
// =========================================================================

package platformforward

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/contracts"
	scanner "github.com/aegisgatesecurity/aegisgate-scanner/pkg/scanner"
)

// fixedTime is used for deterministic test timestamps.
var fixedTime = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

func makeFinding(ruleID, category, severity string, line int) scanner.Finding {
	return scanner.Finding{
		RuleID:     ruleID,
		Category:   category,
		Severity:   scanner.Severity(severity),
		Confidence: 0.95,
		Message:    "test finding for " + ruleID,
		Line:       line,
		Column:     1,
		EndLine:    line,
		EndColumn:  50,
		// MatchedText is set here to verify it's NOT included in the output
		MatchedText: "AKIAIOSFODNN7EXAMPLE",
	}
}

func TestNew_DisabledWhenURLEmpty(t *testing.T) {
	f := New("")
	if f.Enabled() {
		t.Fatal("forwarder should be disabled when URL is empty")
	}
}

func TestNew_EnabledWhenURLSet(t *testing.T) {
	f := New("https://platform.example.com/api/v1/telemetry")
	if !f.Enabled() {
		t.Fatal("forwarder should be enabled when URL is set")
	}
}

func TestForwardFindings_DisabledNoop(t *testing.T) {
	f := New("")
	// Should not panic or send anything
	f.ForwardFindings("file.go", []scanner.Finding{makeFinding("test", "secrets", "high", 1)})
	// If we get here without panic, the test passes
}

func TestFindingsToEvent_PrivacyNoMatchedText(t *testing.T) {
	findings := []scanner.Finding{
		makeFinding("secret_aws_key", "secrets", "critical", 42),
	}
	event := FindingsToEvent("config.yaml", findings, "v0.3.0", fixedTime)

	// Verify event metadata
	if event.Source != contracts.SourceScanner {
		t.Errorf("expected source %q, got %q", contracts.SourceScanner, event.Source)
	}
	if event.Direction != contracts.DirectionScan {
		t.Errorf("expected direction %q, got %q", contracts.DirectionScan, event.Direction)
	}
	if event.Artifact != "config.yaml" {
		t.Errorf("expected artifact 'config.yaml', got %q", event.Artifact)
	}
	if event.TotalDetections != 1 {
		t.Errorf("expected 1 detection, got %d", event.TotalDetections)
	}
	if event.SchemaVersion != "v1" {
		t.Errorf("expected schema v1, got %q", event.SchemaVersion)
	}
	if event.SourceVersion != "v0.3.0" {
		t.Errorf("expected version v0.3.0, got %q", event.SourceVersion)
	}

	// CRITICAL: Verify MatchedText is NOT in the output
	if len(event.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(event.Findings))
	}
	ef := event.Findings[0]
	if ef.RuleID != "secret_aws_key" {
		t.Errorf("expected rule 'secret_aws_key', got %q", ef.RuleID)
	}
	// EventFinding has no MatchedText field — this is the privacy guarantee.
	// We verify by JSON-marshaling and checking the string "AKIA" is NOT present.
	data, _ := json.Marshal(event)
	if contains(string(data), "AKIA") {
		t.Error("MatchedText leaked into event JSON — privacy violation")
	}
}

func TestFindingsToEvent_MultipleCategoriesAggregated(t *testing.T) {
	findings := []scanner.Finding{
		makeFinding("secret_aws_key", "secrets", "critical", 1),
		makeFinding("pii_ssn", "pii-us-core", "high", 10),
		makeFinding("dangerous_py_eval", "dangerous_function", "high", 20),
	}
	event := FindingsToEvent("app.py", findings, "v0.3.0", fixedTime)

	if event.TotalDetections != 3 {
		t.Errorf("expected 3 detections, got %d", event.TotalDetections)
	}

	// Check categories are aggregated
	expectedCats := map[string]bool{"secrets": true, "pii-us-core": true, "dangerous_function": true}
	for _, c := range event.Categories {
		if !expectedCats[c] {
			t.Errorf("unexpected category %q", c)
		}
	}
	if len(event.Categories) != 3 {
		t.Errorf("expected 3 categories, got %d: %v", len(event.Categories), event.Categories)
	}

	// Check severities
	if len(event.Severities) != 2 {
		t.Errorf("expected 2 severities (critical, high), got %d: %v", len(event.Severities), event.Severities)
	}

	// Check rules
	if len(event.Rules) != 3 {
		t.Errorf("expected 3 rules, got %d: %v", len(event.Rules), event.Rules)
	}

	// Check PII categories
	if len(event.PIICategories) != 1 {
		t.Errorf("expected 1 PII category, got %d: %v", len(event.PIICategories), event.PIICategories)
	}

	// Check secret types
	if len(event.SecretTypes) != 1 {
		t.Errorf("expected 1 secret type, got %d: %v", len(event.SecretTypes), event.SecretTypes)
	}
}

func TestFindingsToEvent_ActionFlaggedForCritical(t *testing.T) {
	findings := []scanner.Finding{
		makeFinding("secret_aws_key", "secrets", "critical", 1),
	}
	event := FindingsToEvent("config.yaml", findings, "v0.3.0", fixedTime)
	if event.Action != "flagged" {
		t.Errorf("expected action 'flagged' for critical finding, got %q", event.Action)
	}
}

func TestFindingsToEvent_ActionLoggedForNonCritical(t *testing.T) {
	findings := []scanner.Finding{
		makeFinding("pii_email", "pii-us-core", "medium", 1),
	}
	event := FindingsToEvent("file.txt", findings, "v0.3.0", fixedTime)
	if event.Action != "logged" {
		t.Errorf("expected action 'logged' for non-critical, got %q", event.Action)
	}
}

func TestFindingsToBatch(t *testing.T) {
	results := map[string][]scanner.Finding{
		"file1.py": {makeFinding("dangerous_py_eval", "dangerous_function", "high", 1)},
		"file2.py": {makeFinding("secret_aws_key", "secrets", "critical", 1)},
		"clean.go": {}, // no findings — should be excluded
	}
	batch := FindingsToBatch(results, "v0.3.0", fixedTime)

	if batch.SchemaVersion != "v1" {
		t.Errorf("expected schema v1, got %q", batch.SchemaVersion)
	}
	if batch.Source != contracts.SourceScanner {
		t.Errorf("expected source %q, got %q", contracts.SourceScanner, batch.Source)
	}
	if len(batch.Events) != 2 {
		t.Errorf("expected 2 events (clean.go excluded), got %d", len(batch.Events))
	}
}

func TestForwardFindingsSync_SendsToPlatform(t *testing.T) {
	var receivedBatch contracts.EventBatch
	var receiveCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&receiveCount, 1)
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedBatch)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]int{"accepted": 1, "rejected": 0})
	}))
	defer srv.Close()

	f := NewWithAPIKey(srv.URL+"/api/v1/telemetry", "test-key")
	f.SetVersion("v0.3.0")

	findings := []scanner.Finding{
		makeFinding("secret_aws_key", "secrets", "critical", 42),
	}
	err := f.ForwardFindingsSync("config.yaml", findings)
	if err != nil {
		t.Fatalf("ForwardFindingsSync failed: %v", err)
	}

	if atomic.LoadInt32(&receiveCount) != 1 {
		t.Errorf("expected 1 request, got %d", atomic.LoadInt32(&receiveCount))
	}

	// Verify the batch was received correctly
	if receivedBatch.Source != contracts.SourceScanner {
		t.Errorf("expected source %q, got %q", contracts.SourceScanner, receivedBatch.Source)
	}
	if len(receivedBatch.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(receivedBatch.Events))
	}
	ev := receivedBatch.Events[0]
	if ev.Artifact != "config.yaml" {
		t.Errorf("expected artifact 'config.yaml', got %q", ev.Artifact)
	}
	if ev.TotalDetections != 1 {
		t.Errorf("expected 1 detection, got %d", ev.TotalDetections)
	}
}

func TestForwardBatch_SendsToPlatform(t *testing.T) {
	var receiveCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&receiveCount, 1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	f := New(srv.URL + "/api/v1/telemetry")

	batch := contracts.EventBatch{
		SchemaVersion: "v1",
		Source:        contracts.SourceScanner,
		Events: []contracts.Event{
			{
				ID:              "test-1",
				Source:          contracts.SourceScanner,
				SchemaVersion:   "v1",
				Timestamp:       fixedTime,
				Artifact:        "file1.py",
				TotalDetections: 2,
			},
			{
				ID:              "test-2",
				Source:          contracts.SourceScanner,
				SchemaVersion:   "v1",
				Timestamp:       fixedTime,
				Artifact:        "file2.py",
				TotalDetections: 1,
			},
		},
	}
	err := f.ForwardBatch(batch)
	if err != nil {
		t.Fatalf("ForwardBatch failed: %v", err)
	}
	if atomic.LoadInt32(&receiveCount) != 1 {
		t.Errorf("expected 1 request, got %d", atomic.LoadInt32(&receiveCount))
	}
}

func TestForwardFindingsSync_APIKeyAuth(t *testing.T) {
	var authHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	f := NewWithAPIKey(srv.URL+"/api/v1/telemetry", "secret-api-key")
	findings := []scanner.Finding{makeFinding("test", "secrets", "high", 1)}
	_ = f.ForwardFindingsSync("file.go", findings)

	if authHeader != "Bearer secret-api-key" {
		t.Errorf("expected 'Bearer secret-api-key', got %q", authHeader)
	}
}

func TestForwardFindingsSync_PlatformError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	f := New(srv.URL + "/api/v1/telemetry")
	findings := []scanner.Finding{makeFinding("test", "secrets", "high", 1)}
	err := f.ForwardFindingsSync("file.go", findings)
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
}

func TestHeartbeat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/healthz" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	f := New(srv.URL + "/api/v1/telemetry")
	result := f.Heartbeat()
	if !result.Success {
		t.Errorf("expected heartbeat success, got error: %s", result.Error)
	}
}

func TestHeartbeat_Disabled(t *testing.T) {
	f := New("")
	result := f.Heartbeat()
	if result.Success {
		t.Error("expected heartbeat failure when disabled")
	}
	if result.Error != "platform forwarding disabled" {
		t.Errorf("expected 'platform forwarding disabled', got %q", result.Error)
	}
}

func TestMaskURL(t *testing.T) {
	result := maskURL("https://platform.example.com:9091/api/v1/telemetry")
	if result != "https://platform.example.com/..." {
		t.Errorf("expected masked URL, got %q", result)
	}
}

func TestHealthzURL(t *testing.T) {
	result := healthzURL("https://platform.example.com/api/v1/telemetry")
	if result != "https://platform.example.com/api/v1/healthz" {
		t.Errorf("expected healthz URL, got %q", result)
	}
}

// contains is a simple string contains check (avoiding import of strings for test clarity).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && indexOf(s, substr) >= 0))
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func TestString_Disabled(t *testing.T) {
	f := New("")
	if s := f.String(); s != "platform forwarding disabled" {
		t.Errorf("expected 'platform forwarding disabled', got %q", s)
	}
}

func TestString_Enabled(t *testing.T) {
	f := New("https://platform.example.com/api/v1/telemetry")
	if s := f.String(); s != "platform forwarding → https://platform.example.com/..." {
		t.Errorf("unexpected String output: %q", s)
	}
}

func TestFlush_EmptyBuffer(t *testing.T) {
	f := New("https://example.com/api/v1/telemetry")
	if err := f.Flush(); err != nil {
		t.Errorf("Flush on empty buffer should return nil, got %v", err)
	}
}

func TestFlush_WithBufferedEvents(t *testing.T) {
	var receiveCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&receiveCount, 1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	f := New(srv.URL + "/api/v1/telemetry")

	// Manually add events to the buffer
	f.mu.Lock()
	f.buf = []contracts.Event{
		{ID: "test-1", Source: contracts.SourceScanner, Artifact: "file1.go", TotalDetections: 1},
		{ID: "test-2", Source: contracts.SourceScanner, Artifact: "file2.go", TotalDetections: 2},
	}
	f.mu.Unlock()

	if err := f.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	if atomic.LoadInt32(&receiveCount) != 1 {
		t.Errorf("expected 1 request, got %d", atomic.LoadInt32(&receiveCount))
	}

	// Buffer should be cleared after flush
	f.mu.Lock()
	bufLen := len(f.buf)
	f.mu.Unlock()
	if bufLen != 0 {
		t.Errorf("expected empty buffer after flush, got %d", bufLen)
	}
}

func TestForwardFindings_AsyncSendsToPlatform(t *testing.T) {
	var receivedBatch contracts.EventBatch
	var receiveCount int32
	done := make(chan struct{}, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&receiveCount, 1)
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedBatch)
		w.WriteHeader(http.StatusAccepted)
		select {
		case done <- struct{}{}:
		default:
		}
	}))
	defer srv.Close()

	f := New(srv.URL + "/api/v1/telemetry")
	f.SetVersion("v0.4.0")

	findings := []scanner.Finding{
		makeFinding("secret_aws_key", "secrets", "critical", 42),
	}
	f.ForwardFindings("config.yaml", findings) // async

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for async forward")
	}

	if atomic.LoadInt32(&receiveCount) != 1 {
		t.Errorf("expected 1 request, got %d", atomic.LoadInt32(&receiveCount))
	}
	if len(receivedBatch.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(receivedBatch.Events))
	}
	if receivedBatch.Events[0].Artifact != "config.yaml" {
		t.Errorf("expected artifact 'config.yaml', got %q", receivedBatch.Events[0].Artifact)
	}
}

func TestForwardFindings_DisabledNoFindings(t *testing.T) {
	// When disabled, ForwardFindings should be a no-op
	f := New("")
	f.ForwardFindings("file.go", nil)
	// Should not panic
}

func TestHeartbeat_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	f := New(srv.URL + "/api/v1/telemetry")
	result := f.Heartbeat()
	if result.Success {
		t.Error("expected heartbeat failure for HTTP 500")
	}
	if result.Error == "" {
		t.Error("expected non-empty error message")
	}
}

func TestHeartbeat_ConnectionRefused(t *testing.T) {
	f := New("http://127.0.0.1:1/api/v1/telemetry")
	result := f.Heartbeat()
	if result.Success {
		t.Error("expected heartbeat failure for unreachable host")
	}
	if result.Error == "" {
		t.Error("expected non-empty error message")
	}
}

func TestStartHeartbeatLoop_CancelContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f := New(srv.URL + "/api/v1/telemetry")
	ctx, cancel := context.WithCancel(context.Background())
	results := f.StartHeartbeatLoop(ctx, 50*time.Millisecond)

	// Wait for at least one result
	select {
	case r, ok := <-results:
		if !ok {
			t.Fatal("results channel closed before receiving")
		}
		_ = r
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for heartbeat result")
	}

	// Cancel context — should close the channel
	cancel()
	select {
	case _, ok := <-results:
		if ok {
			t.Error("expected channel to be closed after context cancellation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for channel close after cancel")
	}
}

func TestForwardBatch_DisabledNoop(t *testing.T) {
	f := New("")
	err := f.ForwardBatch(contracts.EventBatch{})
	if err != nil {
		t.Errorf("expected nil error when disabled, got %v", err)
	}
}

func TestForwardFindingsSync_DisabledNoop(t *testing.T) {
	f := New("")
	err := f.ForwardFindingsSync("file.go", []scanner.Finding{makeFinding("test", "secrets", "high", 1)})
	if err != nil {
		t.Errorf("expected nil error when disabled, got %v", err)
	}
}

func TestForwardFindingsSync_NoFindings(t *testing.T) {
	f := New("https://example.com/api/v1/telemetry")
	err := f.ForwardFindingsSync("file.go", nil)
	if err != nil {
		t.Errorf("expected nil error for no findings, got %v", err)
	}
}

func TestMaskURL_Invalid(t *testing.T) {
	result := maskURL("://invalid-url")
	if result != "[invalid-url]" {
		t.Errorf("expected '[invalid-url]', got %q", result)
	}
}

func TestHealthzURL_Invalid(t *testing.T) {
	result := healthzURL("://invalid")
	// Should return the input as-is when parsing fails
	if result == "" {
		t.Error("expected non-empty result for invalid URL")
	}
}
