// SPDX-License-Identifier: Apache-2.0
// Tests for technical debt marker detection patterns.

package detectors

import (
	"strings"
	"testing"
)

func TestDetectTodo_Basic(t *testing.T) {
	text := `// TODO: implement input validation
# FIXME: this is broken
/* HACK: workaround for race condition */
// XXX: need to check permissions
// BUG: crashes on null input
// NOTE: this is informational`

	matches := DetectTodo(text)
	if len(matches) < 6 {
		t.Fatalf("expected at least 6 matches, got %d", len(matches))
	}
}

func TestDetectTodo_TodoPattern(t *testing.T) {
	text := "// TODO: add auth check here"
	matches := DetectTodo(text)
	found := false
	for _, m := range matches {
		if m.Category == "todo_todo" {
			found = true
			if m.Severity != SeverityLow {
				t.Errorf("expected SeverityLow for TODO, got %s", m.Severity)
			}
		}
	}
	if !found {
		t.Error("expected todo_todo match")
	}
}

func TestDetectTodo_FixmePattern(t *testing.T) {
	text := "# FIXME: crashes on large input"
	matches := DetectTodo(text)
	found := false
	for _, m := range matches {
		if m.Category == "todo_fixme" {
			found = true
			if m.Severity != SeverityHigh {
				t.Errorf("expected SeverityHigh for FIXME, got %s", m.Severity)
			}
		}
	}
	if !found {
		t.Error("expected todo_fixme match")
	}
}

func TestDetectTodo_HackPattern(t *testing.T) {
	text := "// HACK: bypassing auth for now"
	matches := DetectTodo(text)
	found := false
	for _, m := range matches {
		if m.Category == "todo_hack" {
			found = true
			if m.Severity != SeverityMedium {
				t.Errorf("expected SeverityMedium for HACK, got %s", m.Severity)
			}
		}
	}
	if !found {
		t.Error("expected todo_hack match")
	}
}

func TestDetectTodo_SecurityMarker(t *testing.T) {
	text := "// TODO: security — need to sanitize input"
	matches := DetectTodo(text)
	found := false
	for _, m := range matches {
		if m.Category == "todo_security" {
			found = true
			if m.Severity != SeverityHigh {
				t.Errorf("expected SeverityHigh for security TODO, got %s", m.Severity)
			}
		}
	}
	if !found {
		t.Error("expected todo_security match")
	}
}

func TestDetectTodo_NotImplemented(t *testing.T) {
	text := "// FIXME: not implemented yet"
	matches := DetectTodo(text)
	found := false
	for _, m := range matches {
		if m.Category == "todo_not_implemented" {
			found = true
		}
	}
	if !found {
		t.Error("expected todo_not_implemented match")
	}
}

func TestDetectTodo_NoFalsePositives(t *testing.T) {
	// Words that contain "todo" but aren't markers.
	text := `The protocol is defined here.
This is a standard procedure.
The document explains the architecture.
Customization options are available.`
	matches := DetectTodo(text)
	if len(matches) > 0 {
		t.Errorf("expected 0 matches for non-marker text, got %d: %+v", len(matches), matches)
	}
}

func TestDetectTodo_RequiresColonOrSpace(t *testing.T) {
	// "TODAY" should not match because it doesn't have : or space after
	text := "TODAY is a good day"
	matches := DetectTodo(text)
	for _, m := range matches {
		if m.Category == "todo_todo" {
			t.Error("TODAY should not match TODO pattern")
		}
	}
}

func TestDetectTodo_InDetectAll(t *testing.T) {
	// Verify that DetectAll includes technical debt markers.
	text := "// TODO: implement this\npassword = \"secret123\""
	matches := DetectAll(text)
	foundTodo := false
	foundSecret := false
	for _, m := range matches {
		if m.Category == "todo_todo" {
			foundTodo = true
		}
		if strings.Contains(m.Category, "secret") || strings.Contains(m.Value, "secret") {
			foundSecret = true
		}
	}
	if !foundTodo {
		t.Error("DetectAll should include TODO markers")
	}
	if !foundSecret {
		t.Error("DetectAll should still find secrets alongside TODOs")
	}
}
