// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestContentHash(t *testing.T) {
	h := ContentHash("hello world")
	if len(h) != 64 { // SHA-256 hex = 64 chars
		t.Errorf("ContentHash length = %d, want 64", len(h))
	}

	// Same content → same hash.
	h2 := ContentHash("hello world")
	if h != h2 {
		t.Error("identical content produced different hashes")
	}

	// Different content → different hash.
	h3 := ContentHash("goodbye world")
	if h == h3 {
		t.Error("different content produced same hash")
	}

	// Empty content → valid hash.
	h4 := ContentHash("")
	if len(h4) != 64 {
		t.Errorf("empty content hash length = %d, want 64", len(h4))
	}
}

func TestPatternSetHash(t *testing.T) {
	defs := []string{"secret_aws_key|AKIA[0-9A-Z]{16}", "secret_github_token|gh[ps]_[A-Za-z0-9]{36}"}
	h1 := PatternSetHash(defs)
	h2 := PatternSetHash(defs)
	if h1 != h2 {
		t.Error("identical pattern sets produced different hashes")
	}

	// Different order → same hash (sorting ensures determinism).
	reversed := []string{"secret_github_token|gh[ps]_[A-Za-z0-9]{36}", "secret_aws_key|AKIA[0-9A-Z]{16}"}
	h3 := PatternSetHash(reversed)
	if h1 != h3 {
		t.Error("reordered pattern sets produced different hashes (should be deterministic)")
	}

	// Modified pattern → different hash.
	modified := []string{"secret_aws_key|AKIA[0-9A-Z]{20}", "secret_github_token|gh[ps]_[A-Za-z0-9]{36}"}
	h4 := PatternSetHash(modified)
	if h1 == h4 {
		t.Error("modified pattern set produced same hash")
	}

	// Added pattern → different hash.
	added := append(defs, "secret_slack_token|xox[baprs]-[A-Za-z0-9-]{10,72}")
	h5 := PatternSetHash(added)
	if h1 == h5 {
		t.Error("added pattern produced same hash")
	}
}

func TestCacheGetPut(t *testing.T) {
	c := &Cache{
		entries: make(map[string]CacheEntry),
		header:  CacheHeader{Version: CacheVersion, ScannerVersion: "test"},
	}

	hash := "abc123"
	findings := []CacheFinding{
		{RuleID: "secret_aws_key", Severity: "critical", Line: 42},
	}

	// Miss before Put.
	got := c.Get(hash)
	if got != nil {
		t.Errorf("Get before Put should return nil, got %d findings", len(got))
	}

	// Put then Get → hit.
	c.Put(hash, findings, 1024)
	got = c.Get(hash)
	if got == nil {
		t.Fatal("Get after Put returned nil")
	}
	if len(got) != 1 {
		t.Fatalf("Get returned %d findings, want 1", len(got))
	}
	if got[0].RuleID != "secret_aws_key" {
		t.Errorf("Get returned wrong RuleID: %s", got[0].RuleID)
	}

	hits, misses := c.Stats()
	if hits != 1 || misses != 1 {
		t.Errorf("Stats = (%d hits, %d misses), want (1, 1)", hits, misses)
	}
}

func TestCacheSaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	header := CacheHeader{
		Version:        CacheVersion,
		ScannerVersion: "0.3.0",
		PatternSetHash: "deadbeef",
		MLEnabled:      false,
	}

	// Create cache with entries.
	c1, err := Load(path, header)
	if err != nil {
		t.Fatalf("Load (new) failed: %v", err)
	}
	if c1.EntryCount() != 0 {
		t.Errorf("new cache has %d entries, want 0", c1.EntryCount())
	}

	findings := []CacheFinding{
		{RuleID: "pii_ssn", Severity: "high", Line: 10},
		{RuleID: "secret_jwt", Severity: "critical", Line: 25},
	}
	c1.Put("hash1", findings, 512)
	c1.Put("hash2", []CacheFinding{}, 256)

	if err := c1.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file exists.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("cache file not created: %v", err)
	}

	// Load into new cache with matching header.
	c2, err := Load(path, header)
	if err != nil {
		t.Fatalf("Load (existing) failed: %v", err)
	}
	if c2.EntryCount() != 2 {
		t.Errorf("loaded cache has %d entries, want 2", c2.EntryCount())
	}

	got := c2.Get("hash1")
	if got == nil || len(got) != 2 {
		t.Errorf("Get(hash1) returned %v, want 2 findings", got)
	}
}

func TestCacheHeaderInvalidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	header1 := CacheHeader{
		Version:        CacheVersion,
		ScannerVersion: "0.3.0",
		PatternSetHash: "aaa",
		MLEnabled:      false,
	}

	// Create and save cache with header1.
	c1, _ := Load(path, header1)
	c1.Put("hash1", []CacheFinding{{RuleID: "test", Line: 1}}, 100)
	c1.Save()

	// Load with different scanner version → should be invalidated.
	header2 := header1
	header2.ScannerVersion = "0.4.0"
	c2, err := Load(path, header2)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if c2.EntryCount() != 0 {
		t.Errorf("cache with mismatched version has %d entries, want 0 (invalidated)", c2.EntryCount())
	}

	// Load with different pattern set hash → should be invalidated.
	header3 := header1
	header3.PatternSetHash = "bbb"
	c3, err := Load(path, header3)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if c3.EntryCount() != 0 {
		t.Errorf("cache with mismatched pattern hash has %d entries, want 0 (invalidated)", c3.EntryCount())
	}

	// Load with different ML enabled → should be invalidated.
	header4 := header1
	header4.MLEnabled = true
	c4, err := Load(path, header4)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if c4.EntryCount() != 0 {
		t.Errorf("cache with mismatched ML flag has %d entries, want 0 (invalidated)", c4.EntryCount())
	}
}

func TestCacheClear(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	// Create a cache file.
	c, _ := Load(path, CacheHeader{Version: CacheVersion, ScannerVersion: "test"})
	c.Put("hash1", []CacheFinding{{RuleID: "test"}}, 100)
	c.Save()

	// Clear it.
	if err := Clear(path); err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	// File should be gone.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("cache file still exists after Clear")
	}

	// Clearing non-existent file should not error.
	if err := Clear(path); err != nil {
		t.Errorf("Clear on non-existent file returned error: %v", err)
	}
}

func TestCacheCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	// Write corrupt JSON.
	os.WriteFile(path, []byte("{not valid json"), 0644)

	// Load should return empty cache (graceful degradation).
	c, err := Load(path, CacheHeader{Version: CacheVersion, ScannerVersion: "test"})
	if err != nil {
		t.Fatalf("Load on corrupt file should not error: %v", err)
	}
	if c.EntryCount() != 0 {
		t.Errorf("corrupt cache has %d entries, want 0", c.EntryCount())
	}
}

func TestCacheDirtyFlag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	c, _ := Load(path, CacheHeader{Version: CacheVersion, ScannerVersion: "test"})

	// Save without changes → should be no-op (not dirty).
	c.Save()

	// File should not exist (no changes to write).
	if _, err := os.Stat(path); err == nil {
		t.Error("cache file created without any changes")
	}

	// Add entry → dirty.
	c.Put("hash1", []CacheFinding{{RuleID: "test"}}, 100)
	c.Save()

	// File should now exist.
	if _, err := os.Stat(path); err != nil {
		t.Error("cache file not created after Put + Save")
	}

	// Load and Save without changes → no-op.
	c2, _ := Load(path, CacheHeader{Version: CacheVersion, ScannerVersion: "test"})
	c2.Save() // should not be dirty
	// We can't easily verify no rewrite, but EntryCount should be preserved.
	if c2.EntryCount() != 1 {
		t.Errorf("reloaded cache has %d entries, want 1", c2.EntryCount())
	}
}

func TestCacheConcurrentAccess(t *testing.T) {
	c := &Cache{
		entries: make(map[string]CacheEntry),
		header:  CacheHeader{Version: CacheVersion, ScannerVersion: "test"},
	}

	// Concurrent Puts.
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			hash := ContentHash(string(rune('a' + idx)))
			c.Put(hash, []CacheFinding{{RuleID: "test"}}, 100)
			done <- true
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}

	// Concurrent Gets.
	for i := 0; i < 10; i++ {
		go func(idx int) {
			hash := ContentHash(string(rune('a' + idx)))
			c.Get(hash)
			done <- true
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}

	if c.EntryCount() != 10 {
		t.Errorf("after concurrent access, entry count = %d, want 10", c.EntryCount())
	}
}

func TestCacheEntryTimestamp(t *testing.T) {
	c := &Cache{
		entries: make(map[string]CacheEntry),
		header:  CacheHeader{Version: CacheVersion, ScannerVersion: "test"},
	}

	before := time.Now().Add(-time.Second)
	c.Put("hash1", []CacheFinding{{RuleID: "test"}}, 100)
	after := time.Now().Add(time.Second)

	c.mu.RLock()
	entry := c.entries["hash1"]
	c.mu.RUnlock()

	if entry.CachedAt.Before(before) || entry.CachedAt.After(after) {
		t.Errorf("CachedAt = %v, expected between %v and %v", entry.CachedAt, before, after)
	}
}

func TestCacheEvict_MaxEntries(t *testing.T) {
	c := &Cache{
		entries:    make(map[string]CacheEntry),
		header:     CacheHeader{Version: CacheVersion, ScannerVersion: "test"},
		MaxEntries: 3,
	}

	// Insert 5 entries with staggered timestamps.
	for i := 0; i < 5; i++ {
		hash := ContentHash(string(rune('a' + i)))
		c.mu.Lock()
		c.entries[hash] = CacheEntry{
			Findings: []CacheFinding{{RuleID: "test"}},
			CachedAt: time.Now().UTC().Add(time.Duration(i) * time.Minute),
		}
		c.dirty = true
		c.mu.Unlock()
	}

	// Put one more — should trigger eviction.
	c.Put(ContentHash("trigger"), []CacheFinding{{RuleID: "test"}}, 100)

	c.mu.RLock()
	count := len(c.entries)
	c.mu.RUnlock()

	if count > 3 {
		t.Errorf("after eviction, entry count = %d, want <= %d", count, c.MaxEntries)
	}

	// The oldest entries (a, b) should have been evicted.
	c.mu.RLock()
	_, hasA := c.entries[ContentHash("a")]
	_, hasB := c.entries[ContentHash("b")]
	c.mu.RUnlock()

	if hasA {
		t.Error("oldest entry 'a' was not evicted")
	}
	if hasB {
		t.Error("second-oldest entry 'b' was not evicted")
	}
}

func TestCacheEvict_MaxAge(t *testing.T) {
	c := &Cache{
		entries: make(map[string]CacheEntry),
		header:  CacheHeader{Version: CacheVersion, ScannerVersion: "test"},
		MaxAge:  1 * time.Hour,
	}

	// Insert an old entry (2 hours ago) and a new entry (1 min ago).
	oldHash := ContentHash("old")
	newHash := ContentHash("new")

	c.mu.Lock()
	c.entries[oldHash] = CacheEntry{
		Findings: []CacheFinding{{RuleID: "old"}},
		CachedAt: time.Now().UTC().Add(-2 * time.Hour),
	}
	c.entries[newHash] = CacheEntry{
		Findings: []CacheFinding{{RuleID: "new"}},
		CachedAt: time.Now().UTC().Add(-1 * time.Minute),
	}
	c.dirty = true
	c.mu.Unlock()

	// Run eviction.
	c.EvictNow()

	c.mu.RLock()
	_, hasOld := c.entries[oldHash]
	_, hasNew := c.entries[newHash]
	count := len(c.entries)
	c.mu.RUnlock()

	if hasOld {
		t.Error("expired entry was not evicted")
	}
	if !hasNew {
		t.Error("fresh entry was incorrectly evicted")
	}
	if count != 1 {
		t.Errorf("entry count = %d, want 1", count)
	}
}

func TestCacheEvict_LoadWithMaxAge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	header := CacheHeader{Version: CacheVersion, ScannerVersion: "test"}

	// Create cache with entries.
	c1, _ := Load(path, header)
	c1.Put("old_hash", []CacheFinding{{RuleID: "old"}}, 100)
	c1.Put("new_hash", []CacheFinding{{RuleID: "new"}}, 100)
	// Manually backdate one entry.
	c1.mu.Lock()
	entry := c1.entries["old_hash"]
	entry.CachedAt = time.Now().UTC().Add(-48 * time.Hour)
	c1.entries["old_hash"] = entry
	c1.mu.Unlock()
	c1.Save()

	// Load with MaxAge = 24 hours.
	c2, err := Load(path, header)
	if err != nil {
		t.Fatal(err)
	}
	c2.MaxAge = 24 * time.Hour
	c2.EvictNow()

	if c2.EntryCount() != 1 {
		t.Errorf("after age eviction on load, entry count = %d, want 1", c2.EntryCount())
	}
}

func TestCacheEvict_NoEvictionWhenUnlimited(t *testing.T) {
	c := &Cache{
		entries:    make(map[string]CacheEntry),
		header:     CacheHeader{Version: CacheVersion, ScannerVersion: "test"},
		MaxEntries: 0, // unlimited
		MaxAge:     0, // no age limit
	}

	for i := 0; i < 100; i++ {
		c.Put(ContentHash(fmt.Sprintf("entry-%d", i)), []CacheFinding{{RuleID: "test"}}, 100)
	}

	if c.EntryCount() != 100 {
		t.Errorf("unlimited cache has %d entries, want 100", c.EntryCount())
	}
}
