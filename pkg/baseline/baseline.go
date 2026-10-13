// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Baseline Suppression
// =========================================================================
//
// Provides baseline file support for suppressing known/accepted findings.
// A baseline file stores findings that have been reviewed and accepted.
// During scanning, findings matching baseline entries are filtered out,
// allowing CI to fail only on NEW findings.
//
// Baseline file format (.aegisgate-baseline.json):
//   {
//     "version": 1,
//     "generated_at": "2026-10-11T12:00:00Z",
//     "entries": [
//       {
//         "rule_id": "secret_aws_key",
//         "artifact": "config/production.yml",
//         "line": 42
//       }
//     ]
//   }
//
// Usage:
//   aegisgate-scanner scan . --baseline .aegisgate-baseline.json
//   aegisgate-scanner scan . --generate-baseline .aegisgate-baseline.json
//
// =========================================================================

package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/scanner"
)

// ---------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------

const Version = 1

// Entry represents a single suppressed finding in the baseline.
type Entry struct {
	RuleID   string `json:"rule_id"`
	Artifact string `json:"artifact"`
	Line     int    `json:"line"`
}

// Baseline holds the complete baseline file content.
type Baseline struct {
	Version     int       `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	Entries     []Entry   `json:"entries"`
}

// ---------------------------------------------------------------------
// Loading and saving
// ---------------------------------------------------------------------

// Load reads a baseline file from the given path.
// Returns an empty baseline if the file does not exist (no error).
func Load(path string) (*Baseline, error) {
	if path == "" {
		return &Baseline{Entries: []Entry{}}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Baseline{Entries: []Entry{}}, nil
		}
		return nil, fmt.Errorf("read baseline file %s: %w", path, err)
	}

	var bl Baseline
	if err := json.Unmarshal(data, &bl); err != nil {
		return nil, fmt.Errorf("parse baseline file %s: %w", path, err)
	}

	if bl.Version != Version {
		return nil, fmt.Errorf("baseline version mismatch: file has %d, expected %d", bl.Version, Version)
	}

	if bl.Entries == nil {
		bl.Entries = []Entry{}
	}

	return &bl, nil
}

// Save writes the baseline to the given path.
func (b *Baseline) Save(path string) error {
	b.Version = Version
	b.GeneratedAt = time.Now().UTC()

	// Sort entries for deterministic output.
	sort.Slice(b.Entries, func(i, j int) bool {
		if b.Entries[i].Artifact != b.Entries[j].Artifact {
			return b.Entries[i].Artifact < b.Entries[j].Artifact
		}
		if b.Entries[i].RuleID != b.Entries[j].RuleID {
			return b.Entries[i].RuleID < b.Entries[j].RuleID
		}
		return b.Entries[i].Line < b.Entries[j].Line
	})

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil { //nosec G306 -- baseline contains security findings
		return fmt.Errorf("write baseline file %s: %w", path, err)
	}

	return nil
}

// ---------------------------------------------------------------------
// Generation from scan results
// ---------------------------------------------------------------------

// FromScanResult creates a baseline from a scan result.
// All current findings are added as baseline entries.
func FromScanResult(result *scanner.ScanResult) *Baseline {
	bl := &Baseline{
		Version:     Version,
		GeneratedAt: time.Now().UTC(),
		Entries:     []Entry{},
	}

	for _, f := range result.Findings {
		bl.Entries = append(bl.Entries, Entry{
			RuleID:   f.RuleID,
			Artifact: f.Artifact,
			Line:     f.Line,
		})
	}

	return bl
}

// ---------------------------------------------------------------------
// Filtering
// ---------------------------------------------------------------------

// entryKey creates a unique key for a baseline entry.
func entryKey(ruleID, artifact string, line int) string {
	return fmt.Sprintf("%s|%s|%d", ruleID, artifact, line)
}

// IsSuppressed checks if a finding matches a baseline entry.
// A finding is suppressed if its rule_id, artifact path, and line number
// all match a baseline entry.
func (b *Baseline) IsSuppressed(ruleID, artifact string, line int) bool {
	if b == nil || len(b.Entries) == 0 {
		return false
	}
	key := entryKey(ruleID, artifact, line)
	for _, e := range b.Entries {
		if entryKey(e.RuleID, e.Artifact, e.Line) == key {
			return true
		}
	}
	return false
}

// Filter removes findings that match baseline entries.
// Returns the filtered findings and a count of suppressed findings.
func (b *Baseline) Filter(findings []scanner.Finding) ([]scanner.Finding, int) {
	if b == nil || len(b.Entries) == 0 {
		return findings, 0
	}

	filtered := make([]scanner.Finding, 0, len(findings))
	suppressed := 0

	for _, f := range findings {
		if b.IsSuppressed(f.RuleID, f.Artifact, f.Line) {
			suppressed++
			continue
		}
		filtered = append(filtered, f)
	}

	return filtered, suppressed
}
