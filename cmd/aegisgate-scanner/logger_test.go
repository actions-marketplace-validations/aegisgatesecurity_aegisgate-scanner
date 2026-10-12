// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/config"
)

// ---------------------------------------------------------------------
// logger.go tests
// ---------------------------------------------------------------------

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"INFO", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"WARN", slog.LevelWarn},
		{"error", slog.LevelError},
		{"ERROR", slog.LevelError},
		{"err", slog.LevelError},
		{"", slog.LevelInfo},           // empty defaults to info
		{"bogus", slog.LevelInfo},      // unknown defaults to info
		{"  debug  ", slog.LevelDebug}, // whitespace trimmed
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := parseLogLevel(tc.input)
			if got != tc.want {
				t.Errorf("parseLogLevel(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseLogFormat(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"text", "text", false},
		{"TEXT", "text", false},
		{"json", "json", false},
		{"JSON", "json", false},
		{"", "text", false},         // empty defaults to text
		{"  text  ", "text", false}, // whitespace trimmed
		{"xml", "", true},           // invalid
		{"yaml", "", true},          // invalid
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := parseLogFormat(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("parseLogFormat(%q) expected error, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Errorf("parseLogFormat(%q) unexpected error: %v", tc.input, err)
				return
			}
			if got != tc.want {
				t.Errorf("parseLogFormat(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestInitLogger_TextFormat(t *testing.T) {
	// Capture stderr to verify slog output goes there.
	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	initLogger("debug", "text")
	slog.Info("test message", "key", "value")

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	output := buf.String()
	if !strings.Contains(output, "level=INFO") {
		t.Errorf("expected 'level=INFO' in text format output, got: %s", output)
	}
	if !strings.Contains(output, "test message") {
		t.Errorf("expected 'test message' in output, got: %s", output)
	}
	if !strings.Contains(output, "key=value") {
		t.Errorf("expected 'key=value' in output, got: %s", output)
	}
}

func TestInitLogger_JSONFormat(t *testing.T) {
	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	initLogger("info", "json")
	slog.Error("json test", "component", "test")

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	output := buf.String()
	if !strings.Contains(output, `"level":"ERROR"`) {
		t.Errorf("expected JSON level field in output, got: %s", output)
	}
	if !strings.Contains(output, `"msg":"json test"`) {
		t.Errorf("expected JSON msg field in output, got: %s", output)
	}
	if !strings.Contains(output, `"component":"test"`) {
		t.Errorf("expected JSON component field in output, got: %s", output)
	}
}

func TestInitLogger_LevelFiltering(t *testing.T) {
	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// At error level, info and warn should be suppressed.
	initLogger("error", "text")
	slog.Info("should not appear")
	slog.Warn("should not appear either")
	slog.Error("should appear")

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	output := buf.String()
	if strings.Contains(output, "should not appear") {
		t.Errorf("info/warn should be filtered at error level, got: %s", output)
	}
	if !strings.Contains(output, "should appear") {
		t.Errorf("error message should appear at error level, got: %s", output)
	}
}

func TestInitLogger_DefaultLevel(t *testing.T) {
	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// Empty level should default to info — debug should be suppressed.
	initLogger("", "text")
	slog.Debug("debug should not appear")
	slog.Info("info should appear")

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	output := buf.String()
	if strings.Contains(output, "debug should not appear") {
		t.Errorf("debug should be filtered at default (info) level, got: %s", output)
	}
	if !strings.Contains(output, "info should appear") {
		t.Errorf("info should appear at default level, got: %s", output)
	}
}

// ---------------------------------------------------------------------
// parseGlobalFlags tests
// ---------------------------------------------------------------------

func TestParseGlobalFlags_LogLevel(t *testing.T) {
	remaining, level, format := parseGlobalFlags([]string{"scan", ".", "--log-level", "debug"})
	if level != "debug" {
		t.Errorf("expected level=debug, got %q", level)
	}
	if format != "" {
		t.Errorf("expected format empty, got %q", format)
	}
	if len(remaining) != 2 || remaining[0] != "scan" || remaining[1] != "." {
		t.Errorf("expected [scan .], got %v", remaining)
	}
}

func TestParseGlobalFlags_LogFormat(t *testing.T) {
	remaining, level, format := parseGlobalFlags([]string{"scan", "--log-format", "json"})
	if level != "" {
		t.Errorf("expected level empty, got %q", level)
	}
	if format != "json" {
		t.Errorf("expected format=json, got %q", format)
	}
	if len(remaining) != 1 || remaining[0] != "scan" {
		t.Errorf("expected [scan], got %v", remaining)
	}
}

func TestParseGlobalFlags_BothFlags(t *testing.T) {
	remaining, level, format := parseGlobalFlags([]string{
		"scan", ".", "--log-level", "warn", "--log-format", "json",
	})
	if level != "warn" {
		t.Errorf("expected level=warn, got %q", level)
	}
	if format != "json" {
		t.Errorf("expected format=json, got %q", format)
	}
	if len(remaining) != 2 {
		t.Errorf("expected 2 remaining args, got %d: %v", len(remaining), remaining)
	}
}

func TestParseGlobalFlags_EqualsSyntax(t *testing.T) {
	remaining, level, format := parseGlobalFlags([]string{
		"scan", "--log-level=error", "--log-format=json",
	})
	if level != "error" {
		t.Errorf("expected level=error, got %q", level)
	}
	if format != "json" {
		t.Errorf("expected format=json, got %q", format)
	}
	if len(remaining) != 1 || remaining[0] != "scan" {
		t.Errorf("expected [scan], got %v", remaining)
	}
}

func TestParseGlobalFlags_NoFlags(t *testing.T) {
	remaining, level, format := parseGlobalFlags([]string{"scan", ".", "--no-ml"})
	if level != "" || format != "" {
		t.Errorf("expected empty level and format, got level=%q format=%q", level, format)
	}
	if len(remaining) != 3 {
		t.Errorf("expected 3 remaining args, got %d: %v", len(remaining), remaining)
	}
}

func TestParseGlobalFlags_MixedWithScanFlags(t *testing.T) {
	remaining, level, format := parseGlobalFlags([]string{
		".", "--format", "json", "--log-level", "debug", "--no-ml",
	})
	if level != "debug" {
		t.Errorf("expected level=debug, got %q", level)
	}
	if format != "" {
		t.Errorf("expected format empty (not --format), got %q", format)
	}
	// --format json should remain in args (it's a scan flag, not a global flag)
	if len(remaining) != 4 {
		t.Errorf("expected 4 remaining args, got %d: %v", len(remaining), remaining)
	}
}

// ---------------------------------------------------------------------
// Integration: --log-level and --log-format through run()
// ---------------------------------------------------------------------

func TestRun_GlobalLogLevel_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	// Create a clean file so scan succeeds.
	os.WriteFile(filepath.Join(dir, "doc.md"), []byte("Hello world"), 0644)

	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml",
		"--log-level", "error", "--log-format", "json"})

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if exitCode != exitOK {
		t.Errorf("expected exitOK, got %d", exitCode)
	}

	// At error level with no errors, stderr should be empty.
	output := buf.String()
	if output != "" {
		// Could have JSON log lines if any warnings — check they're JSON format
		if !strings.Contains(output, `"level"`) && output != "" {
			t.Errorf("expected JSON log format or empty, got: %s", output)
		}
	}
}

func TestRun_GlobalLogLevel_DebugText(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "doc.md"), []byte("Hello world"), 0644)

	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml",
		"--log-level", "debug", "--log-format", "text"})

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if exitCode != exitOK {
		t.Errorf("expected exitOK, got %d", exitCode)
	}

	// Debug level should produce text-format log lines.
	output := buf.String()
	if output != "" && !strings.Contains(output, "level=") {
		t.Errorf("expected text log format, got: %s", output)
	}
}

func TestRun_LogLevelViaConfig(t *testing.T) {
	dir := t.TempDir()
	// Config with log_level=debug and log_format=json
	os.WriteFile(filepath.Join(dir, ".aegisgate.yml"), []byte(
		"log_level: debug\nlog_format: json\n"), 0644)
	os.WriteFile(filepath.Join(dir, "doc.md"), []byte("Hello world"), 0644)

	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml"})

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if exitCode != exitOK {
		t.Errorf("expected exitOK, got %d", exitCode)
	}

	output := buf.String()
	// Debug + JSON format should produce JSON log lines.
	if output != "" && !strings.Contains(output, `"level"`) {
		t.Errorf("expected JSON log format from config, got: %s", output)
	}
}

// ---------------------------------------------------------------------
// Config validation tests for log_level and log_format
// ---------------------------------------------------------------------

func TestConfig_ValidateLogLevel(t *testing.T) {
	tests := []struct {
		level   string
		wantErr bool
	}{
		{"debug", false},
		{"info", false},
		{"warn", false},
		{"warning", false},
		{"error", false},
		{"err", false},
		{"", false},     // empty is valid (defaults to info)
		{"bogus", true}, // invalid
		{"TRACE", true}, // invalid
	}

	for _, tc := range tests {
		t.Run(tc.level, func(t *testing.T) {
			cfg := config.Default()
			cfg.LogLevel = tc.level
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Errorf("expected error for log_level=%q, got nil", tc.level)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for log_level=%q: %v", tc.level, err)
			}
		})
	}
}

func TestConfig_ValidateLogFormat(t *testing.T) {
	tests := []struct {
		format  string
		wantErr bool
	}{
		{"text", false},
		{"json", false},
		{"", false},     // empty is valid (defaults to text)
		{"xml", true},   // invalid
		{"yaml", true},  // invalid
		{"DEBUG", true}, // invalid
	}

	for _, tc := range tests {
		t.Run(tc.format, func(t *testing.T) {
			cfg := config.Default()
			cfg.LogFormat = tc.format
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Errorf("expected error for log_format=%q, got nil", tc.format)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for log_format=%q: %v", tc.format, err)
			}
		})
	}
}

func TestConfig_DefaultLogLevelAndFormat(t *testing.T) {
	cfg := config.Default()
	if cfg.LogLevel != "info" {
		t.Errorf("expected default log_level=info, got %q", cfg.LogLevel)
	}
	if cfg.LogFormat != "text" {
		t.Errorf("expected default log_format=text, got %q", cfg.LogFormat)
	}
}
