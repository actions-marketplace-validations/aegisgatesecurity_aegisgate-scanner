// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Content-Hash Result Cache
// =========================================================================
//
// Persists per-file scan results keyed by content hash (SHA-256). When the
// same file content is encountered in a future scan, cached findings are
// returned instantly without re-running regex, entropy, or ML detection.
//
// Design principles:
//   - Content-addressed: key is SHA-256(file_content), not file path.
//     Renaming a file without changing content still hits the cache.
//   - Stores RAW findings (pre-filtering). Severity thresholds, rule
//     disabling, baseline suppression, and inline suppressions are all
//     applied post-cache, so changing those options does NOT invalidate
//     the cache.
//   - Header validation: scanner_version + pattern_set_hash + ml_enabled
//     are stored in the cache header. A mismatch invalidates the entire
//     cache on load.
//   - Single JSON file, zero external dependencies.
//   - Thread-safe via sync.RWMutex (multiple readers, exclusive writes).
//
// =========================================================================

package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------

// CacheVersion is the cache file format version. Bump when the on-disk
// format changes in a backwards-incompatible way.
const CacheVersion = 1

// ---------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------

// CacheHeader contains global metadata that invalidates the entire cache
// when mismatched on load.
type CacheHeader struct {
	Version        int    `json:"version"`
	ScannerVersion string `json:"scanner_version"`
	PatternSetHash string `json:"pattern_set_hash"`
	MLEnabled      bool   `json:"ml_enabled"`
}

// CacheEntry stores the cached findings for a single content hash.
type CacheEntry struct {
	Findings []CacheFinding `json:"findings"`
	Size     int64          `json:"size"`
	CachedAt time.Time      `json:"cached_at"`
}

// CacheFinding is a serialization-friendly representation of a scanner
// Finding. It contains only the fields needed to reconstruct the finding
// without re-scanning. This avoids a circular import with pkg/scanner.
type CacheFinding struct {
	RuleID         string  `json:"rule_id"`
	Category       string  `json:"category"`
	Severity       string  `json:"severity"`
	Confidence     float64 `json:"confidence"`
	Message        string  `json:"message"`
	Line           int     `json:"line"`
	Column         int     `json:"column"`
	EndLine        int     `json:"end_line"`
	EndColumn      int     `json:"end_column"`
	MatchedText    string  `json:"matched_text"`
	DetectionLayer string  `json:"detection_layer"`
}

// CacheFile is the on-disk JSON structure.
type CacheFile struct {
	Header  CacheHeader           `json:"header"`
	Entries map[string]CacheEntry `json:"entries"`
}

// Cache provides content-addressed storage of scan results.
// It is safe for concurrent use by multiple goroutines.
type Cache struct {
	mu      sync.RWMutex
	path    string
	header  CacheHeader
	entries map[string]CacheEntry
	hits    atomic.Int64
	misses  atomic.Int64
	dirty   bool
}

// ---------------------------------------------------------------------
// Content hashing
// ---------------------------------------------------------------------

// ContentHash computes the SHA-256 hash of content and returns the
// lowercase hex-encoded string.
func ContentHash(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}

// PatternSetHash computes a deterministic hash of the pattern set.
// patternDefs is a slice of "name|regex" strings for all compiled patterns.
func PatternSetHash(patternDefs []string) string {
	// Sort for determinism regardless of input order.
	sorted := make([]string, len(patternDefs))
	copy(sorted, patternDefs)
	sort.Strings(sorted)

	h := sha256.New()
	for _, d := range sorted {
		h.Write([]byte(d))
		h.Write([]byte{0}) // separator
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------------
// Loading and saving
// ---------------------------------------------------------------------

// Load reads a cache file from disk and validates its header.
// If the file does not exist, returns a new empty cache (no error).
// If the header does not match the expected header, the cache is
// treated as invalidated — a new empty cache is returned.
func Load(path string, expectedHeader CacheHeader) (*Cache, error) {
	c := &Cache{
		path:    path,
		header:  expectedHeader,
		entries: make(map[string]CacheEntry),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// No cache file — start fresh.
			return c, nil
		}
		return nil, fmt.Errorf("read cache file %s: %w", path, err)
	}

	var cf CacheFile
	if err := json.Unmarshal(data, &cf); err != nil {
		// Corrupt cache — start fresh rather than failing the scan.
		return c, nil
	}

	// Validate header. Any mismatch invalidates the entire cache.
	if cf.Header.Version != expectedHeader.Version ||
		cf.Header.ScannerVersion != expectedHeader.ScannerVersion ||
		cf.Header.PatternSetHash != expectedHeader.PatternSetHash ||
		cf.Header.MLEnabled != expectedHeader.MLEnabled {
		// Stale cache — start fresh.
		return c, nil
	}

	c.entries = cf.Entries
	if c.entries == nil {
		c.entries = make(map[string]CacheEntry)
	}
	return c, nil
}

// Save writes the cache to disk if there are unsaved changes.
// Returns nil if the cache is clean (no changes since load).
func (c *Cache) Save() error {
	c.mu.RLock()
	if !c.dirty {
		c.mu.RUnlock()
		return nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	cf := CacheFile{
		Header:  c.header,
		Entries: c.entries,
	}

	data, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal cache: %w", err)
	}

	if err := os.WriteFile(c.path, data, 0644); err != nil {
		return fmt.Errorf("write cache file %s: %w", c.path, err)
	}

	c.dirty = false
	return nil
}

// Clear removes the cache file from disk.
func Clear(path string) error {
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("remove cache file %s: %w", path, err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Get / Put
// ---------------------------------------------------------------------

// Get returns the cached findings for a content hash, or nil if not found.
// Thread-safe. Increments hit/miss counters.
func (c *Cache) Get(contentHash string) []CacheFinding {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[contentHash]
	if ok {
		c.hits.Add(1)
		return entry.Findings
	}
	c.misses.Add(1)
	return nil
}

// Put stores findings for a content hash.
// Thread-safe. Marks the cache as dirty (needs saving).
func (c *Cache) Put(contentHash string, findings []CacheFinding, size int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[contentHash] = CacheEntry{
		Findings: findings,
		Size:     size,
		CachedAt: time.Now().UTC(),
	}
	c.dirty = true
}

// ---------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------

// Stats returns cache hit and miss counts.
func (c *Cache) Stats() (hits, misses int) {
	return int(c.hits.Load()), int(c.misses.Load())
}

// EntryCount returns the number of entries in the cache.
func (c *Cache) EntryCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
