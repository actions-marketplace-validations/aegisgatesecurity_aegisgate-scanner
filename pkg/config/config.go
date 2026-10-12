// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Configuration
// =========================================================================
//
// Parses .aegisgate.yml configuration files for the scanner.
// Supports:
//   - Ignore paths (glob patterns)
//   - File extension filters
//   - Severity thresholds
//   - ML toggle and threshold
//   - Output format selection
//   - Max file size
//   - Max findings per file
//
// Configuration is loaded from (in priority order):
//   1. CLI flags (highest priority)
//   2. .aegisgate.yml in scan root
//   3. Built-in defaults (lowest priority)
//
// =========================================================================

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aegisgatesecurity/aegisgate-scanner/internal/detectors"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/artifacts"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/scanner"
)

// ---------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------

// Config holds the scanner configuration.
type Config struct {
	// IgnorePaths are glob patterns to exclude from scanning.
	IgnorePaths []string `yaml:"ignore_paths"`

	// Extensions restricts scanning to specific file extensions.
	// If empty, all supported extensions are scanned.
	Extensions []string `yaml:"extensions"`

	// MaxFileSize is the maximum file size in bytes to scan.
	// Default: 10 MB.
	MaxFileSize int64 `yaml:"max_file_size"`

	// FollowSymlinks controls whether symlinks are followed.
	FollowSymlinks bool `yaml:"follow_symlinks"`

	// MinSeverity is the minimum severity to report.
	// Options: critical, high, medium, low.
	// Default: low (report all).
	MinSeverity string `yaml:"min_severity"`

	// EnableML controls whether ML threat detection is used.
	EnableML bool `yaml:"enable_ml"`

	// MLThreshold is the minimum ML score to report.
	// If 0, uses the detector's calibrated default.
	MLThreshold float64 `yaml:"ml_threshold"`

	// MaxFindingsPerFile limits findings per file.
	// 0 = unlimited.
	MaxFindingsPerFile int `yaml:"max_findings_per_file"`

	// OutputFormat selects the output format.
	// Options: sarif, json, text.
	// Default: text.
	OutputFormat string `yaml:"output_format"`

	// ColorOutput controls ANSI color in text output.
	ColorOutput bool `yaml:"color_output"`

	// ModelPath is the path to the ONNX model file.
	// If empty, uses the default path.
	ModelPath string `yaml:"model_path"`

	// BaselinePath is the path to a baseline file for suppressing
	// known/accepted findings. If empty, no baseline is used.
	BaselinePath string `yaml:"baseline_path"`

	// CustomRules are user-defined detection patterns.
	// Each rule has a name, regex pattern, severity, category, and description.
	CustomRules []CustomRuleConfig `yaml:"custom_rules"`

	// RespectGitIgnore controls whether .gitignore files are respected
	// when walking directories. Default: true.
	RespectGitIgnore bool `yaml:"respect_gitignore"`

	// FailOnSeverity is the minimum severity that causes a non-zero exit code.
	// Findings below this severity are reported but don't fail the scan.
	// Options: critical, high, medium, low.
	// Default: low (any finding fails).
	FailOnSeverity string `yaml:"fail_on_severity"`

	// DisableRules is a list of rule IDs to disable (skip during scanning).
	DisableRules []string `yaml:"disable_rules"`
}

// CustomRuleConfig defines a user-created detection rule in the config file.
type CustomRuleConfig struct {
	Name        string `yaml:"name"`
	Pattern     string `yaml:"pattern"`
	Severity    string `yaml:"severity"`
	Category    string `yaml:"category"`
	Description string `yaml:"description"`
}

// ---------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------

// Default returns the default configuration.
func Default() *Config {
	return &Config{
		IgnorePaths:        []string{},
		Extensions:         []string{},
		MaxFileSize:        10 * 1024 * 1024, // 10 MB
		FollowSymlinks:     false,
		MinSeverity:        "low",
		EnableML:           true,
		MLThreshold:        0.50,
		MaxFindingsPerFile: 0, // unlimited
		OutputFormat:       "text",
		ColorOutput:        true,
		ModelPath:          "",
		BaselinePath:       "",
		RespectGitIgnore:   true,
		FailOnSeverity:     "low",
		DisableRules:       []string{},
	}
}

// ---------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------

// configFileName is the configuration file name.
const configFileName = ".aegisgate.yml"

// altConfigFileNames are alternative config file names checked in order.
var altConfigFileNames = []string{
	".aegisgate.yml",
	".aegisgate.yaml",
	".aegisgate-scanner.yml",
	".aegisgate-scanner.yaml",
}

// Load reads configuration from the scan root directory.
// If no config file is found, returns defaults.
func Load(scanRoot string) (*Config, error) {
	cfg := Default()

	configPath := findConfigFile(scanRoot)
	if configPath == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config file %s: %w", configPath, err)
	}

	if err := parseYAML(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config file %s: %w", configPath, err)
	}

	// Validate the configuration.
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config in %s: %w", configPath, err)
	}

	return cfg, nil
}

// findConfigFile searches for a config file in the scan root.
func findConfigFile(scanRoot string) string {
	for _, name := range altConfigFileNames {
		path := filepath.Join(scanRoot, name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// LoadFile loads configuration from an explicit file path. This allows
// users to specify a config file via --config flag that may be located
// outside the scan root (e.g., a central security config repository).
func LoadFile(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file %s: %w", path, err)
	}

	if err := parseYAML(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config file %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config in %s: %w", path, err)
	}

	return cfg, nil
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	// Validate min severity.
	switch strings.ToLower(c.MinSeverity) {
	case "critical", "high", "medium", "low", "":
	default:
		return fmt.Errorf("invalid min_severity: %s (must be critical, high, medium, or low)", c.MinSeverity)
	}

	// Validate output format.
	switch strings.ToLower(c.OutputFormat) {
	case "sarif", "json", "text", "html", "pr-comment", "github-actions", "sbom", "":
	default:
		return fmt.Errorf("invalid output_format: %s (must be sarif, json, text, html, pr-comment, github-actions, or sbom)", c.OutputFormat)
	}

	// Validate ML threshold.
	if c.MLThreshold < 0 || c.MLThreshold > 1 {
		return fmt.Errorf("invalid ml_threshold: %f (must be between 0 and 1)", c.MLThreshold)
	}

	// Validate max file size.
	if c.MaxFileSize < 0 {
		return fmt.Errorf("invalid max_file_size: %d (must be >= 0)", c.MaxFileSize)
	}

	// Validate fail_on_severity.
	switch strings.ToLower(c.FailOnSeverity) {
	case "critical", "high", "medium", "low", "":
	default:
		return fmt.Errorf("invalid fail_on_severity: %s (must be critical, high, medium, or low)", c.FailOnSeverity)
	}

	// Validate custom rules.
	for i, rule := range c.CustomRules {
		if rule.Name == "" {
			return fmt.Errorf("custom_rules[%d]: name is required", i)
		}
		if rule.Pattern == "" {
			return fmt.Errorf("custom_rules[%d]: pattern is required", i)
		}
		switch strings.ToLower(rule.Severity) {
		case "critical", "high", "medium", "low", "":
		default:
			return fmt.Errorf("custom_rules[%d]: invalid severity %s", i, rule.Severity)
		}
	}

	return nil
}

// ---------------------------------------------------------------------
// Conversion to scanner/artifacts options
// ---------------------------------------------------------------------

// ToWalkOptions converts the config to artifact walker options.
func (c *Config) ToWalkOptions(root string) artifacts.WalkOptions {
	return artifacts.WalkOptions{
		Root:             root,
		IgnorePaths:      c.IgnorePaths,
		MaxFileSize:      c.MaxFileSize,
		FollowSymlinks:   c.FollowSymlinks,
		Extensions:       c.Extensions,
		RespectGitIgnore: c.RespectGitIgnore,
	}
}

// ToScanOptions converts the config to scanner options.
func (c *Config) ToScanOptions() scanner.ScanOptions {
	return scanner.ScanOptions{
		EnableML:           c.EnableML,
		MLThreshold:        c.MLThreshold,
		MinSeverity:        parseSeverity(c.MinSeverity),
		MaxFindingsPerFile: c.MaxFindingsPerFile,
		DisableRules:       c.DisableRules,
		Concurrency:        0, // default sequential; CLI can override
	}
}

// parseSeverity converts a string to detectors.Severity.
func parseSeverity(s string) detectors.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return detectors.SeverityCritical
	case "high":
		return detectors.SeverityHigh
	case "medium":
		return detectors.SeverityMedium
	case "low":
		return detectors.SeverityLow
	default:
		return "" // no filter
	}
}

// ToDetectorPatterns converts custom rule configs to detector PatternDef slice.
func (c *Config) ToDetectorPatterns() []detectors.PatternDef {
	if len(c.CustomRules) == 0 {
		return nil
	}
	defs := make([]detectors.PatternDef, len(c.CustomRules))
	for i, rule := range c.CustomRules {
		defs[i] = detectors.PatternDef{
			Name:        rule.Name,
			Regex:       rule.Pattern,
			Severity:    parseSeverity(rule.Severity),
			Category:    detectors.Category(rule.Category),
			Description: rule.Description,
		}
	}
	return defs
}

// ---------------------------------------------------------------------
// Minimal YAML parser (no external dependencies)
// ---------------------------------------------------------------------

// parseYAML parses a minimal YAML subset for .aegisgate.yml.
// Supports:
//   - key: value (scalar)
//   - key: [a, b, c] (inline list)
//   - key:
//   - item1
//   - item2 (block list)
//   - # comments
//   - quoted strings
//
// This is NOT a full YAML parser — it handles only the subset needed
// for scanner configuration. This avoids any external dependencies.
func parseYAML(data []byte, cfg *Config) error {
	lines := strings.Split(string(data), "\n")
	currentKey := ""
	var currentRule *CustomRuleConfig
	inCustomRules := false

	for _, rawLine := range lines {
		// Compute indentation from the raw line before processing.
		indent := 0
		for _, c := range rawLine {
			if c == ' ' {
				indent++
			} else if c == '\t' {
				indent += 4 // treat tab as 4 spaces
			} else {
				break
			}
		}

		line := rawLine

		// Strip comments.
		if idx := strings.Index(line, "#"); idx >= 0 {
			// Don't strip # inside quotes.
			beforeHash := line[:idx]
			if !strings.Contains(beforeHash, "\"") || strings.Count(beforeHash, "\"")%2 == 0 {
				line = beforeHash
			}
		}
		line = strings.TrimSpace(line)

		// Skip empty lines.
		if line == "" {
			continue
		}

		// Handle custom_rules block (list of maps).
		if inCustomRules {
			if indent == 0 {
				// We've left the custom_rules block — finalize current rule.
				if currentRule != nil {
					cfg.CustomRules = append(cfg.CustomRules, *currentRule)
					currentRule = nil
				}
				inCustomRules = false
				// Fall through to normal processing below.
			} else {
				if strings.HasPrefix(line, "- ") {
					// New custom rule entry.
					if currentRule != nil {
						cfg.CustomRules = append(cfg.CustomRules, *currentRule)
					}
					currentRule = &CustomRuleConfig{}
					rest := strings.TrimSpace(line[2:])
					if rest != "" {
						parseCustomRuleKV(currentRule, rest)
					}
				} else if currentRule != nil {
					// Property of the current custom rule.
					parseCustomRuleKV(currentRule, line)
				}
				continue
			}
		}

		// Block list item (string lists).
		if strings.HasPrefix(line, "- ") {
			item := strings.TrimSpace(line[2:])
			item = unquote(item)
			if currentKey != "" {
				switch currentKey {
				case "ignore_paths":
					cfg.IgnorePaths = append(cfg.IgnorePaths, item)
				case "extensions":
					cfg.Extensions = append(cfg.Extensions, item)
				case "disable_rules":
					cfg.DisableRules = append(cfg.DisableRules, item)
				}
			}
			continue
		}

		// Key: value pair.
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}

		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		currentKey = key

		if value == "" {
			// Block list or nested map — handled by subsequent lines.
			if key == "custom_rules" {
				inCustomRules = true
			}
			continue
		}

		// Inline list: [a, b, c]
		if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
			items := parseInlineList(value)
			switch key {
			case "ignore_paths":
				cfg.IgnorePaths = append(cfg.IgnorePaths, items...)
			case "extensions":
				cfg.Extensions = append(cfg.Extensions, items...)
			case "disable_rules":
				cfg.DisableRules = append(cfg.DisableRules, items...)
			}
			continue
		}

		value = unquote(value)

		switch key {
		case "max_file_size":
			n, err := parseInt64(value)
			if err != nil {
				return fmt.Errorf("invalid max_file_size value: %s", value)
			}
			cfg.MaxFileSize = n
		case "follow_symlinks":
			cfg.FollowSymlinks = parseBool(value)
		case "min_severity":
			cfg.MinSeverity = value
		case "enable_ml":
			cfg.EnableML = parseBool(value)
		case "ml_threshold":
			n, err := parseFloat64(value)
			if err != nil {
				return fmt.Errorf("invalid ml_threshold value: %s", value)
			}
			cfg.MLThreshold = n
		case "max_findings_per_file":
			n, err := parseInt(value)
			if err != nil {
				return fmt.Errorf("invalid max_findings_per_file value: %s", value)
			}
			cfg.MaxFindingsPerFile = n
		case "output_format":
			cfg.OutputFormat = value
		case "color_output":
			cfg.ColorOutput = parseBool(value)
		case "model_path":
			cfg.ModelPath = value
		case "baseline_path":
			cfg.BaselinePath = value
		case "respect_gitignore":
			cfg.RespectGitIgnore = parseBool(value)
		case "fail_on_severity":
			cfg.FailOnSeverity = value
		}
	}

	// Finalize any pending custom rule at end of file.
	if currentRule != nil {
		cfg.CustomRules = append(cfg.CustomRules, *currentRule)
	}

	return nil
}

// parseCustomRuleKV parses a single key:value pair into a CustomRuleConfig.
func parseCustomRuleKV(rule *CustomRuleConfig, kv string) {
	idx := strings.Index(kv, ":")
	if idx < 0 {
		return
	}
	key := strings.TrimSpace(kv[:idx])
	value := strings.TrimSpace(kv[idx+1:])
	value = unquote(value)
	switch key {
	case "name":
		rule.Name = value
	case "pattern":
		rule.Pattern = value
	case "severity":
		rule.Severity = value
	case "category":
		rule.Category = value
	case "description":
		rule.Description = value
	}
}

// parseInlineList parses "[a, b, c]" into a slice of strings.
func parseInlineList(s string) []string {
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = unquote(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// unquote removes surrounding quotes from a string.
func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// parseBool parses a YAML boolean value.
func parseBool(s string) bool {
	switch strings.ToLower(s) {
	case "true", "yes", "on", "1":
		return true
	default:
		return false
	}
}

// parseInt64 parses a string to int64.
func parseInt64(s string) (int64, error) {
	var n int64
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

// parseInt parses a string to int.
func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

// parseFloat64 parses a string to float64.
func parseFloat64(s string) (float64, error) {
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	return f, err
}
