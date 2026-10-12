// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"path/filepath"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-scanner/internal/detectors"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/artifacts"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/cache"
)

func TestCache_BasicHitMiss(t *testing.T) {
	sc, err := New(ScanOptions{EnableML: false})
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	header := ComputeCacheHeader("test", false)
	c, err := cache.Load("", header)
	if err != nil {
		t.Fatal(err)
	}

	content := `AKIAIOSFODNN7EXAMPLE
This is a test file with a fake AWS key.
`
	art := artifacts.Artifact{
		Path:    "test.txt",
		Content: content,
		Class:   artifacts.ClassGeneric,
	}

	opts := ScanOptions{Cache: c}

	// First scan — should be a cache miss.
	findings1 := sc.ScanArtifact(art, opts)
	if len(findings1) == 0 {
		t.Fatal("expected findings on first scan")
	}
	hits, misses := c.Stats()
	if hits != 0 || misses != 1 {
		t.Errorf("after first scan: hits=%d misses=%d, want (0, 1)", hits, misses)
	}

	// Second scan — should be a cache hit with identical findings.
	findings2 := sc.ScanArtifact(art, opts)
	if len(findings2) != len(findings1) {
		t.Fatalf("cache hit findings count = %d, want %d", len(findings2), len(findings1))
	}
	for i := range findings1 {
		if findings1[i].RuleID != findings2[i].RuleID {
			t.Errorf("finding %d RuleID mismatch: %s vs %s", i, findings1[i].RuleID, findings2[i].RuleID)
		}
		if findings1[i].Line != findings2[i].Line {
			t.Errorf("finding %d Line mismatch: %d vs %d", i, findings1[i].Line, findings2[i].Line)
		}
		if findings1[i].MatchedText != findings2[i].MatchedText {
			t.Errorf("finding %d MatchedText mismatch: %q vs %q", i, findings1[i].MatchedText, findings2[i].MatchedText)
		}
	}

	hits, misses = c.Stats()
	if hits != 1 || misses != 1 {
		t.Errorf("after second scan: hits=%d misses=%d, want (1, 1)", hits, misses)
	}
}

func TestCache_DifferentContentIsMiss(t *testing.T) {
	sc, err := New(ScanOptions{EnableML: false})
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	header := ComputeCacheHeader("test", false)
	c, _ := cache.Load("", header)

	art1 := artifacts.Artifact{Path: "a.txt", Content: "AKIAIOSFODNN7EXAMPLE\n", Class: artifacts.ClassGeneric}
	art2 := artifacts.Artifact{Path: "b.txt", Content: "Different content entirely\n", Class: artifacts.ClassGeneric}

	opts := ScanOptions{Cache: c}

	sc.ScanArtifact(art1, opts)
	sc.ScanArtifact(art2, opts)

	hits, misses := c.Stats()
	if hits != 0 || misses != 2 {
		t.Errorf("two different files: hits=%d misses=%d, want (0, 2)", hits, misses)
	}
}

func TestCache_RenamedFileIsHit(t *testing.T) {
	sc, err := New(ScanOptions{EnableML: false})
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	header := ComputeCacheHeader("test", false)
	c, _ := cache.Load("", header)

	content := "AKIAIOSFODNN7EXAMPLE\n"
	art1 := artifacts.Artifact{Path: "original.txt", Content: content, Class: artifacts.ClassGeneric}
	art2 := artifacts.Artifact{Path: "renamed.txt", Content: content, Class: artifacts.ClassGeneric}

	opts := ScanOptions{Cache: c}

	sc.ScanArtifact(art1, opts) // miss
	sc.ScanArtifact(art2, opts) // hit — same content, different path

	hits, misses := c.Stats()
	if hits != 1 || misses != 1 {
		t.Errorf("renamed file: hits=%d misses=%d, want (1, 1)", hits, misses)
	}
}

func TestCache_SeverityFilterDoesNotInvalidate(t *testing.T) {
	sc, err := New(ScanOptions{EnableML: false})
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	header := ComputeCacheHeader("test", false)
	c, _ := cache.Load("", header)

	content := "AKIAIOSFODNN7EXAMPLE\nThis has a secret and a TODO: fix this later\n"
	art := artifacts.Artifact{Path: "test.txt", Content: content, Class: artifacts.ClassGeneric}

	// First scan — no severity filter (see all findings).
	optsAll := ScanOptions{Cache: c}
	findingsAll := sc.ScanArtifact(art, optsAll)
	totalAll := len(findingsAll)

	// Second scan — filter to critical only. Should still be a cache hit
	// (severity filtering is post-cache).
	optsCritical := ScanOptions{
		Cache:       c,
		MinSeverity: detectors.SeverityCritical,
	}
	findingsCritical := sc.ScanArtifact(art, optsCritical)

	if len(findingsCritical) >= totalAll {
		t.Errorf("critical filter returned %d findings, expected fewer than %d", len(findingsCritical), totalAll)
	}

	hits, misses := c.Stats()
	if misses != 1 {
		t.Errorf("expected 1 miss (first scan), got %d", misses)
	}
	if hits != 1 {
		t.Errorf("expected 1 hit (second scan with different severity), got %d", hits)
	}
}

func TestCache_DisableRulesDoesNotInvalidate(t *testing.T) {
	sc, err := New(ScanOptions{EnableML: false})
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	header := ComputeCacheHeader("test", false)
	c, _ := cache.Load("", header)

	content := "AKIAIOSFODNN7EXAMPLE\nTODO: fix this\n"
	art := artifacts.Artifact{Path: "test.txt", Content: content, Class: artifacts.ClassGeneric}

	// First scan — all rules.
	opts1 := ScanOptions{Cache: c}
	findings1 := sc.ScanArtifact(art, opts1)

	// Second scan — disable todo rules. Should be a cache hit.
	opts2 := ScanOptions{
		Cache:        c,
		DisableRules: []string{"todo_todo", "todo_fixme"},
	}
	findings2 := sc.ScanArtifact(art, opts2)

	if len(findings2) >= len(findings1) {
		t.Errorf("disabled rules filter returned %d, expected fewer than %d", len(findings2), len(findings1))
	}

	hits, _ := c.Stats()
	if hits != 1 {
		t.Errorf("expected 1 cache hit with disabled rules, got %d", hits)
	}
}

func TestCache_EmptyContentNotCached(t *testing.T) {
	sc, err := New(ScanOptions{EnableML: false})
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	header := ComputeCacheHeader("test", false)
	c, _ := cache.Load("", header)

	art := artifacts.Artifact{Path: "empty.txt", Content: "", Class: artifacts.ClassGeneric}
	opts := ScanOptions{Cache: c}

	sc.ScanArtifact(art, opts)

	hits, misses := c.Stats()
	if hits != 0 || misses != 0 {
		t.Errorf("empty content: hits=%d misses=%d, want (0, 0) — empty content not cached", hits, misses)
	}
}

func TestCache_NilCacheWorks(t *testing.T) {
	sc, err := New(ScanOptions{EnableML: false})
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	art := artifacts.Artifact{Path: "test.txt", Content: "AKIAIOSFODNN7EXAMPLE\n", Class: artifacts.ClassGeneric}
	opts := ScanOptions{Cache: nil} // no cache

	findings := sc.ScanArtifact(art, opts)
	if len(findings) == 0 {
		t.Fatal("expected findings without cache")
	}
}

func TestCache_SaveAndReload(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "test-cache.json")

	header := ComputeCacheHeader("test", false)

	// First scanner — scan and save cache.
	sc1, _ := New(ScanOptions{EnableML: false})
	defer sc1.Close()

	c1, _ := cache.Load(cachePath, header)
	content := "AKIAIOSFODNN7EXAMPLE\n"
	art := artifacts.Artifact{Path: "test.txt", Content: content, Class: artifacts.ClassGeneric}

	sc1.ScanArtifact(art, ScanOptions{Cache: c1})
	c1.Save()

	// Second scanner — load cache and scan same content.
	sc2, _ := New(ScanOptions{EnableML: false})
	defer sc2.Close()

	c2, _ := cache.Load(cachePath, header)
	findings := sc2.ScanArtifact(art, ScanOptions{Cache: c2})

	if len(findings) == 0 {
		t.Fatal("expected findings from reloaded cache")
	}

	hits, misses := c2.Stats()
	if misses != 0 {
		t.Errorf("reloaded cache should have 0 misses, got %d", misses)
	}
	if hits != 1 {
		t.Errorf("reloaded cache should have 1 hit, got %d", hits)
	}
}
