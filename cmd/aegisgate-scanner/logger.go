// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Structured Logging Setup
// =========================================================================
//
// Initializes Go's standard library slog logger with configurable level
// and output format. All diagnostic messages (errors, warnings, progress
// info) use slog instead of ad-hoc fmt.Fprintf(os.Stderr, ...) calls.
//
// User-facing output (scan results, version, doctor, init) continues to
// use fmt.Print* to stdout — only diagnostic/logging goes through slog.
//
// Log levels:   debug, info, warn, error
// Log formats:  text (default), json
// Output sink:  stderr (always — stdout is reserved for scan results)
//
// =========================================================================

package main

import (
	"log/slog"
	"os"
	"strings"
)

// initLogger configures the global slog logger with the specified level
// and format. It is called once at startup from run() before any command
// is dispatched.
//
// level:  "debug", "info", "warn", "error" (case-insensitive, default: info)
// format: "text", "json" (case-insensitive, default: text)
func initLogger(level, format string) {
	slogLevel := parseLogLevel(level)
	opts := &slog.HandlerOptions{
		Level: slogLevel,
	}

	var handler slog.Handler
	if strings.ToLower(format) == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	slog.SetDefault(slog.New(handler))
}

// parseLogLevel converts a string level name to slog.Level.
// Unknown values default to info.
func parseLogLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error", "err":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// parseLogFormat validates a log format string.
// Returns the canonical form ("text" or "json") or an error.
func parseLogFormat(format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text":
		return "text", nil
	case "json":
		return "json", nil
	default:
		return "", ErrInvalidLogFormat
	}
}
