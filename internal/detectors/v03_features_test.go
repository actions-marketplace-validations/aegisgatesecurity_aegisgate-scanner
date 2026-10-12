// SPDX-License-Identifier: Apache-2.0
package detectors

import (
	"testing"
)

func TestLanguageFromExtension(t *testing.T) {
	tests := []struct {
		ext  string
		want Language
	}{
		{".py", LangPython},
		{".js", LangJS},
		{".ts", LangTS},
		{".go", LangGo},
		{".yaml", LangYAML},
		{".html", LangHTML},
		{".unknown", LangGeneric},
		{"", LangGeneric},
	}
	for _, tc := range tests {
		got := LanguageFromExtension(tc.ext)
		if got != tc.want {
			t.Errorf("LanguageFromExtension(%q) = %q, want %q", tc.ext, got, tc.want)
		}
	}
}

func TestLanguageFromPath(t *testing.T) {
	tests := []struct {
		path string
		want Language
	}{
		{"foo/bar.py", LangPython},
		{"test.ts", LangTS},
		{"config.yaml", LangYAML},
		{"noextension", LangGeneric},
		{"/abs/path/to/file.go", LangGo},
	}
	for _, tc := range tests {
		got := LanguageFromPath(tc.path)
		if got != tc.want {
			t.Errorf("LanguageFromPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestFilterByLanguage(t *testing.T) {
	patterns := []compiledPattern{
		{Name: "py_only", Languages: []Language{LangPython}},
		{Name: "js_ts", Languages: []Language{LangJS, LangTS}},
		{Name: "universal", Languages: nil},
	}

	// LangAny returns all
	all := filterByLanguage(patterns, LangAny)
	if len(all) != 3 {
		t.Errorf("LangAny: expected 3, got %d", len(all))
	}

	// Python: py_only + universal
	py := filterByLanguage(patterns, LangPython)
	if len(py) != 2 {
		t.Errorf("Python: expected 2, got %d", len(py))
	}

	// JS: js_ts + universal
	js := filterByLanguage(patterns, LangJS)
	if len(js) != 2 {
		t.Errorf("JS: expected 2, got %d", len(js))
	}

	// Go: universal only
	goLang := filterByLanguage(patterns, LangGo)
	if len(goLang) != 1 {
		t.Errorf("Go: expected 1, got %d", len(goLang))
	}
}

func TestDetectAllWithLanguage(t *testing.T) {
	// Python-specific pattern should only trigger on Python
	pyText := "eval(os.system('cat /etc/passwd'))"
	yamlText := "command: eval(os.system('cat /etc/passwd'))"

	// With Python language, dangerous_py_eval should fire
	pyMatches := DetectAllWithLanguage(pyText, LangPython)
	pyHasEval := false
	for _, m := range pyMatches {
		if m.Category == "dangerous_py_eval" {
			pyHasEval = true
		}
	}
	if !pyHasEval {
		t.Error("expected dangerous_py_eval to fire on Python text with Python language")
	}

	// With YAML language, dangerous_py_eval should NOT fire (it's Python-only)
	yamlMatches := DetectAllWithLanguage(yamlText, LangYAML)
	yamlHasEval := false
	for _, m := range yamlMatches {
		if m.Category == "dangerous_py_eval" {
			yamlHasEval = true
		}
	}
	if yamlHasEval {
		t.Error("dangerous_py_eval should NOT fire on YAML text with YAML language")
	}

	// With LangAny, all patterns fire
	anyMatches := DetectAllWithLanguage(pyText, LangAny)
	anyHasEval := false
	for _, m := range anyMatches {
		if m.Category == "dangerous_py_eval" {
			anyHasEval = true
		}
	}
	if !anyHasEval {
		t.Error("dangerous_py_eval should fire with LangAny")
	}
}

func TestMergeCategorySmall(t *testing.T) {
	// XSS patterns are small enough to merge
	mc := mergeCategory("xss", CompiledXSSPatterns)
	if mc.combined == nil {
		t.Error("expected XSS merge to succeed")
	}
	if mc.combined.NumSubexp() != len(CompiledXSSPatterns) {
		t.Errorf("expected %d groups, got %d", len(CompiledXSSPatterns), mc.combined.NumSubexp())
	}
}

func TestMergeCategoryLarge(t *testing.T) {
	// Compliance patterns are too large to merge
	mc := mergeCategory("compliance", CompiledCompliancePatterns)
	if mc.combined != nil {
		t.Error("expected compliance merge to fail (too large), but it succeeded")
	}
}

func TestDetectWithMerged(t *testing.T) {
	// Test that merged regex produces same results as sequential
	text := `<script>alert('xss')</script><img src=x onerror=alert(1)>`

	mc := mergeCategory("xss", CompiledXSSPatterns)
	if mc.combined == nil {
		t.Fatal("XSS merge failed")
	}

	mergedMatches := detectWithMerged(text, &mc)
	seqMatches := detectSequential(text, CompiledXSSPatterns)

	if len(mergedMatches) != len(seqMatches) {
		t.Errorf("merged: %d matches, sequential: %d matches", len(mergedMatches), len(seqMatches))
	}

	// Verify categories match
	for i := 0; i < len(mergedMatches) && i < len(seqMatches); i++ {
		if mergedMatches[i].Category != seqMatches[i].Category {
			t.Errorf("match %d: merged=%s, sequential=%s", i, mergedMatches[i].Category, seqMatches[i].Category)
		}
		if mergedMatches[i].Index != seqMatches[i].Index {
			t.Errorf("match %d index: merged=%d, sequential=%d", i, mergedMatches[i].Index, seqMatches[i].Index)
		}
	}
}
