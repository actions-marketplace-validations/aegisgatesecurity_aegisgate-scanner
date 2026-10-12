// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — SARIF Output Formatter
// =========================================================================
//
// Produces SARIF (Static Analysis Results Interchange Format) 2.1.0
// output compatible with GitHub Code Scanning. The output includes:
//   - Tool information (name, version, rules)
//   - Results with precise locations (line, column)
//   - Severity mapping (SARIF levels: error, warning, note)
//   - Rule metadata for GitHub UI display
//
// SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
//
// =========================================================================

package output

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/aegisgatesecurity/aegisgate-scanner/internal/detectors"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/artifacts"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/scanner"
)

// ---------------------------------------------------------------------
// SARIF schema types (SARIF 2.1.0)
// ---------------------------------------------------------------------

// sarifLog is the top-level SARIF log object.
type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

// sarifRun represents a single run of the scanner.
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

// sarifTool describes the scanner tool.
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

// sarifDriver provides tool metadata and rule definitions.
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

// sarifRule defines a detection rule for GitHub UI display.
type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	FullDescription  sarifMessage   `json:"fullDescription,omitempty"`
	Help             sarifMessage   `json:"help,omitempty"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       sarifRuleProps `json:"properties,omitempty"`
}

// sarifRuleProps holds rule properties for GitHub UI, including CWE and
// OWASP LLM Top 10 references from the rule metadata database.
type sarifRuleProps struct {
	Tags      []string `json:"tags,omitempty"`
	Precision string   `json:"precision,omitempty"`
	Severity  string   `json:"severity,omitempty"`
	Category  string   `json:"category,omitempty"`
	CWE       []int    `json:"cwe,omitempty"`
	OWASP     string   `json:"owasp,omitempty"`
}

// sarifResult represents a single finding.
type sarifResult struct {
	RuleID              string                   `json:"ruleId"`
	Level               string                   `json:"level"`
	Message             sarifMessage             `json:"message"`
	Locations           []sarifLocation          `json:"locations"`
	PartialFingerprints sarifPartialFingerprints `json:"partialFingerprints,omitempty"`
}

// sarifMessage is a SARIF message object.
type sarifMessage struct {
	Text string `json:"text"`
}

// sarifLocation describes where a finding was detected.
type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

// sarifPhysicalLocation provides file and region information.
type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

// sarifArtifactLocation identifies the file.
type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// sarifRegion defines the precise location within the file.
type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

// sarifPartialFingerprints provides fingerprinting for result deduplication.
type sarifPartialFingerprints struct {
	PrimaryLocationLineHash string `json:"primaryLocationLineHash,omitempty"`
}

// ---------------------------------------------------------------------
// Formatter
// ---------------------------------------------------------------------

// FormatSARIF produces SARIF 2.1.0 JSON output from scan results.
func FormatSARIF(result *scanner.ScanResult, toolVersion string) ([]byte, error) {
	// Build rule definitions from findings.
	rules := buildSARIFRules(result)

	// Build results.
	var sarifResults []sarifResult
	for _, f := range result.Findings {
		sr := sarifResult{
			RuleID: f.RuleID,
			Level:  severityToSARIFLevel(f.Severity),
			Message: sarifMessage{
				Text: f.Message,
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: f.Artifact,
						},
						Region: sarifRegion{
							StartLine:   f.Line,
							StartColumn: f.Column,
							EndLine:     f.EndLine,
							EndColumn:   f.EndColumn,
						},
					},
				},
			},
			PartialFingerprints: sarifPartialFingerprints{
				PrimaryLocationLineHash: fmt.Sprintf("%s:%d:%s", f.Artifact, f.Line, f.RuleID),
			},
		}
		sarifResults = append(sarifResults, sr)
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "aegisgate-scanner",
						Version:        toolVersion,
						InformationURI: "https://aegisgatesecurity.io",
						Rules:          rules,
					},
				},
				Results: sarifResults,
			},
		},
	}

	return json.MarshalIndent(log, "", "  ")
}

// buildSARIFRules extracts unique rule definitions from findings.
func buildSARIFRules(result *scanner.ScanResult) []sarifRule {
	ruleMap := make(map[string]sarifRule)

	for _, f := range result.Findings {
		if _, exists := ruleMap[f.RuleID]; exists {
			continue
		}

		meta := GetRuleMetadataWithDefault(f.RuleID)

		rule := sarifRule{
			ID:   f.RuleID,
			Name: strings.ReplaceAll(f.RuleID, "_", "-"),
			ShortDescription: sarifMessage{
				Text: meta.Description,
			},
			FullDescription: sarifMessage{
				Text: meta.Description,
			},
			Help: sarifMessage{
				Text: meta.Remediation,
			},
			HelpURI: "https://aegisgatesecurity.io/docs/scanner/rules/" + f.RuleID,
			Properties: sarifRuleProps{
				Tags:      buildRuleTags(f),
				Precision: "high",
				Severity:  string(f.Severity),
				Category:  f.Category,
				CWE:       meta.CWE,
				OWASP:     meta.OWASPLLMTop,
			},
		}

		ruleMap[f.RuleID] = rule
	}

	// Sort rules by ID for deterministic output.
	rules := make([]sarifRule, 0, len(ruleMap))
	for _, r := range ruleMap {
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})

	return rules
}

// buildRuleTags generates tags for a finding based on its category.
func buildRuleTags(f scanner.Finding) []string {
	tags := []string{"security"}

	switch f.Category {
	case "ml-prompt-injection":
		tags = append(tags, "prompt-injection", "ai-security", "owasp-llm01")
	case "secrets":
		tags = append(tags, "secrets", "credentials")
	case "pii-us-core", "pii-us-extended", "pii-financial", "pii-international":
		tags = append(tags, "pii", "privacy")
	case "xss":
		tags = append(tags, "xss", "injection")
	case "compliance":
		tags = append(tags, "compliance")
	case "ot-protocols":
		tags = append(tags, "ot", "ics", "infrastructure")
	}

	if f.DetectionLayer == "ml" {
		tags = append(tags, "ml")
	}

	return tags
}

// severityToSARIFLevel maps AegisGate severity to SARIF level.
func severityToSARIFLevel(sev detectors.Severity) string {
	switch sev {
	case detectors.SeverityCritical, detectors.SeverityHigh:
		return "error"
	case detectors.SeverityMedium:
		return "warning"
	case detectors.SeverityLow:
		return "note"
	default:
		return "warning"
	}
}

// ---------------------------------------------------------------------
// Convenience
// ---------------------------------------------------------------------

// ArtifactClassToSARIFTags maps artifact classes to SARIF tag strings.
func ArtifactClassToSARIFTags(class artifacts.ArtifactClass) []string {
	switch class {
	case artifacts.ClassRAGDocument:
		return []string{"rag", "knowledge-base"}
	case artifacts.ClassTrainingData:
		return []string{"training-data", "dataset"}
	case artifacts.ClassModelConfig:
		return []string{"model-config", "configuration"}
	case artifacts.ClassAgentSkill:
		return []string{"agent-skill", "tool-definition"}
	default:
		return []string{"generic"}
	}
}
