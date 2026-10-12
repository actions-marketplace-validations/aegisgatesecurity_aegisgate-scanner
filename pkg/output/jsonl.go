// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — JSONL (NDJSON) Output Formatter
// =========================================================================
//
// Produces newline-delimited JSON output — one JSON object per line per
// finding, plus a final summary line. This format is ideal for:
//   - Piping to jq, grep, awk for ad-hoc analysis
//   - Streaming ingestion into Splunk, ELK, Datadog, Loki
//   - Real-time monitoring dashboards
//   - Diffing scan results between commits
//
// Each finding is a self-contained JSON object on a single line. The
// final line is a summary object with "type": "summary" to distinguish
// it from finding objects ("type": "finding").
//
// =========================================================================

package output

import (
	"encoding/json"
	"time"

	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/scanner"
)

// jsonlFinding is a single finding in JSONL output.
type jsonlFinding struct {
	Type           string  `json:"type"` // always "finding"
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
	Remediation    string  `json:"remediation,omitempty"`
}

// jsonlSummary is the final summary line in JSONL output.
type jsonlSummary struct {
	Type              string         `json:"type"` // always "summary"
	Tool              string         `json:"tool"`
	Version           string         `json:"version"`
	Root              string         `json:"root"`
	Timestamp         string         `json:"timestamp"`
	Duration          string         `json:"duration"`
	FilesScanned      int            `json:"files_scanned"`
	FilesWithFindings int            `json:"files_with_findings"`
	TotalFindings     int            `json:"total_findings"`
	MLInferences      int            `json:"ml_inferences"`
	BySeverity        map[string]int `json:"by_severity"`
	ByCategory        map[string]int `json:"by_category"`
	ByLayer           map[string]int `json:"by_layer"`
}

// FormatJSONL produces newline-delimited JSON (NDJSON) output from scan
// results. Each finding is emitted as a single-line JSON object, followed
// by a summary object as the final line.
func FormatJSONL(result *scanner.ScanResult, root, toolVersion string) ([]byte, error) {
	encoder := json.NewEncoder(new(jsonlBuffer))
	encoder.SetEscapeHTML(false)

	var buf jsonlBuffer

	// Emit one JSON object per finding.
	for _, f := range result.Findings {
		jf := jsonlFinding{
			Type:           "finding",
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
			Remediation:    f.Remediation,
		}
		line, err := json.Marshal(jf)
		if err != nil {
			return nil, err
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}

	// Emit summary as the final line.
	summary := jsonlSummary{
		Type:              "summary",
		Tool:              "aegisgate-scanner",
		Version:           toolVersion,
		Root:              root,
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
		Duration:          result.Duration.String(),
		FilesScanned:      result.Stats.FilesScanned,
		FilesWithFindings: result.Stats.FilesWithFindings,
		TotalFindings:     result.Stats.TotalFindings,
		MLInferences:      result.Stats.MLInferences,
		BySeverity:        make(map[string]int),
		ByCategory:        make(map[string]int),
		ByLayer:           make(map[string]int),
	}
	for sev, count := range result.Stats.BySeverity {
		summary.BySeverity[string(sev)] = count
	}
	for cat, count := range result.Stats.ByCategory {
		summary.ByCategory[cat] = count
	}
	for layer, count := range result.Stats.ByLayer {
		summary.ByLayer[layer] = count
	}

	line, err := json.Marshal(summary)
	if err != nil {
		return nil, err
	}
	buf.Write(line)
	buf.WriteByte('\n')

	return buf.Bytes(), nil
}

// jsonlBuffer is a simple byte buffer for JSONL output.
type jsonlBuffer struct {
	data []byte
}

func (b *jsonlBuffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *jsonlBuffer) WriteByte(c byte) error {
	b.data = append(b.data, c)
	return nil
}

func (b *jsonlBuffer) Bytes() []byte {
	return b.data
}
