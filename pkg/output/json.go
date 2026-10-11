// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — JSON Output Formatter
// =========================================================================
//
// Produces structured JSON output with full finding details, artifact
// metadata, and scan statistics. Suitable for programmatic consumption
// and CI/CD pipeline integration.
//
// =========================================================================

package output

import (
	"encoding/json"
	"time"

	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/scanner"
)

// ---------------------------------------------------------------------
// JSON schema types
// ---------------------------------------------------------------------

// jsonReport is the top-level JSON report.
type jsonReport struct {
	Tool     jsonTool      `json:"tool"`
	Scan     jsonScanInfo  `json:"scan"`
	Findings []jsonFinding `json:"findings"`
	Stats    jsonStats     `json:"stats"`
}

// jsonTool describes the scanner tool.
type jsonTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// jsonScanInfo provides scan metadata.
type jsonScanInfo struct {
	Root      string `json:"root"`
	Timestamp string `json:"timestamp"`
	Duration  string `json:"duration"`
}

// jsonFinding is a single finding in JSON output.
type jsonFinding struct {
	Artifact       string  `json:"artifact"`
	ArtifactClass  string  `json:"artifact_class"`
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
	MLScore        float64 `json:"ml_score,omitempty"`
	MLVariant      string  `json:"ml_variant,omitempty"`
}

// jsonStats holds scan statistics.
type jsonStats struct {
	FilesScanned      int            `json:"files_scanned"`
	FilesWithFindings int            `json:"files_with_findings"`
	TotalFindings     int            `json:"total_findings"`
	MLInferences      int            `json:"ml_inferences"`
	BySeverity        map[string]int `json:"by_severity"`
	ByCategory        map[string]int `json:"by_category"`
	ByLayer           map[string]int `json:"by_layer"`
}

// ---------------------------------------------------------------------
// Formatter
// ---------------------------------------------------------------------

// FormatJSON produces JSON output from scan results.
func FormatJSON(result *scanner.ScanResult, root, toolVersion string) ([]byte, error) {
	report := jsonReport{
		Tool: jsonTool{
			Name:    "aegisgate-scanner",
			Version: toolVersion,
		},
		Scan: jsonScanInfo{
			Root:      root,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Duration:  result.Duration.String(),
		},
		Findings: make([]jsonFinding, 0, len(result.Findings)),
		Stats: jsonStats{
			FilesScanned:      result.Stats.FilesScanned,
			FilesWithFindings: result.Stats.FilesWithFindings,
			TotalFindings:     result.Stats.TotalFindings,
			MLInferences:      result.Stats.MLInferences,
			BySeverity:        make(map[string]int),
			ByCategory:        make(map[string]int),
			ByLayer:           make(map[string]int),
		},
	}

	for _, f := range result.Findings {
		jf := jsonFinding{
			Artifact:       f.Artifact,
			ArtifactClass:  string(f.ArtifactClass),
			RuleID:         f.RuleID,
			Category:       f.Category,
			Severity:       string(f.Severity),
			Confidence:     f.Confidence,
			Message:        f.Message,
			Line:           f.Line,
			Column:         f.Column,
			EndLine:        f.EndLine,
			EndColumn:      f.EndColumn,
			MatchedText:    f.MatchedText,
			DetectionLayer: f.DetectionLayer,
			MLScore:        f.MLScore,
			MLVariant:      f.MLVariant,
		}
		report.Findings = append(report.Findings, jf)
	}

	for sev, count := range result.Stats.BySeverity {
		report.Stats.BySeverity[string(sev)] = count
	}
	for cat, count := range result.Stats.ByCategory {
		report.Stats.ByCategory[cat] = count
	}
	for layer, count := range result.Stats.ByLayer {
		report.Stats.ByLayer[layer] = count
	}

	return json.MarshalIndent(report, "", "  ")
}
