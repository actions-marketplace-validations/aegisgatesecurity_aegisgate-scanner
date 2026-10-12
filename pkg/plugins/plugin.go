// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Plugin System for Custom Detectors
// =========================================================================
//
// Provides a plugin interface for loading custom detection rules from
// YAML pattern files in the .aegisgate-plugins/ directory.
//
// Plugin format (YAML):
//   name: my_custom_detector
//   rules:
//     - name: custom_api_key
//       pattern: "my_api_key_[a-z0-9]+"
//       severity: high
//       category: secrets
//       description: "Detects custom API keys"
//
// The plugin system uses the existing detector engine's custom pattern
// registration. No external dependencies are required.
//
// =========================================================================

package plugins

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aegisgatesecurity/aegisgate-scanner/internal/detectors"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/scanner"
)

// ---------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------

// DetectorPlugin is the interface for custom detection plugins.
type DetectorPlugin interface {
	// Name returns the plugin name.
	Name() string

	// Detect scans text and returns findings.
	Detect(text string) []scanner.Finding

	// Init initializes the plugin with configuration.
	Init(config map[string]string) error
}

// PluginRule defines a single detection rule within a plugin.
type PluginRule struct {
	Name        string `yaml:"name"`
	Pattern     string `yaml:"pattern"`
	Severity    string `yaml:"severity"`
	Category    string `yaml:"category"`
	Description string `yaml:"description"`
}

// PluginConfig holds the configuration for a YAML-based plugin.
type PluginConfig struct {
	Name  string       `yaml:"name"`
	Rules []PluginRule `yaml:"rules"`
}

// ---------------------------------------------------------------------
// YAML Plugin (file-based)
// ---------------------------------------------------------------------

// YAMLPlugin is a plugin loaded from a YAML pattern file.
type YAMLPlugin struct {
	config PluginConfig
	rules  []compiledPluginRule
	name   string
}

// compiledPluginRule holds a compiled regex pattern with metadata.
type compiledPluginRule struct {
	Name        string
	Severity    detectors.Severity
	Category    string
	Description string
	Regex       *regexp.Regexp
}

// Name returns the plugin name.
func (p *YAMLPlugin) Name() string {
	return p.name
}

// Init initializes the plugin by compiling all regex patterns.
func (p *YAMLPlugin) Init(config map[string]string) error {
	// Config can override the plugin name.
	if name, ok := config["name"]; ok {
		p.name = name
	}
	return p.compileRules()
}

// Detect scans text using the plugin's compiled rules and returns findings.
func (p *YAMLPlugin) Detect(text string) []scanner.Finding {
	if len(p.rules) == 0 || text == "" {
		return nil
	}

	var findings []scanner.Finding
	lines := strings.Split(text, "\n")

	for lineNum, line := range lines {
		for _, rule := range p.rules {
			matches := rule.Regex.FindAllStringIndex(line, -1)
			for _, idx := range matches {
				value := line[idx[0]:idx[1]]
				if len(value) > 200 {
					value = value[:200] + "..."
				}
				findings = append(findings, scanner.Finding{
					RuleID:         rule.Name,
					Category:       rule.Category,
					Severity:       rule.Severity,
					Confidence:     1.0,
					Message:        fmt.Sprintf("%s: detected %s pattern", rule.Severity, rule.Name),
					Line:           lineNum + 1,
					Column:         idx[0] + 1,
					EndLine:        lineNum + 1,
					EndColumn:      idx[1] + 1,
					MatchedText:    value,
					DetectionLayer: "plugin",
				})
			}
		}
	}

	return findings
}

// compileRules compiles all regex patterns in the plugin config.
func (p *YAMLPlugin) compileRules() error {
	p.rules = make([]compiledPluginRule, 0, len(p.config.Rules))

	for _, rule := range p.config.Rules {
		if rule.Name == "" {
			return fmt.Errorf("plugin rule missing name")
		}
		if rule.Pattern == "" {
			return fmt.Errorf("plugin rule %s missing pattern", rule.Name)
		}

		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex for rule %s: %w", rule.Name, err)
		}

		p.rules = append(p.rules, compiledPluginRule{
			Name:        rule.Name,
			Severity:    parsePluginSeverity(rule.Severity),
			Category:    rule.Category,
			Description: rule.Description,
			Regex:       re,
		})
	}

	return nil
}

// parsePluginSeverity converts a string to detectors.Severity.
func parsePluginSeverity(s string) detectors.Severity {
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
		return detectors.SeverityMedium // default to medium
	}
}

// Rules returns the plugin's rule definitions.
func (p *YAMLPlugin) Rules() []PluginRule {
	return p.config.Rules
}

// ---------------------------------------------------------------------
// Plugin loading
// ---------------------------------------------------------------------

// LoadPlugin loads a YAML plugin from a file path.
func LoadPlugin(path string) (*YAMLPlugin, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read plugin file %s: %w", path, err)
	}

	cfg, err := ParsePluginConfig(data)
	if err != nil {
		return nil, fmt.Errorf("parse plugin file %s: %w", path, err)
	}

	plugin := &YAMLPlugin{
		config: *cfg,
		name:   cfg.Name,
	}

	if err := plugin.compileRules(); err != nil {
		return nil, fmt.Errorf("compile plugin %s: %w", cfg.Name, err)
	}

	return plugin, nil
}

// LoadPluginsFromDir loads all YAML plugin files from a directory.
// Returns a slice of loaded plugins and any errors encountered.
// Files must have .yaml or .yml extension.
func LoadPluginsFromDir(dir string) ([]*YAMLPlugin, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // Directory doesn't exist — no plugins.
		}
		return nil, fmt.Errorf("read plugin directory %s: %w", dir, err)
	}

	var plugins []*YAMLPlugin

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		plugin, err := LoadPlugin(path)
		if err != nil {
			return nil, fmt.Errorf("load plugin %s: %w", entry.Name(), err)
		}

		plugins = append(plugins, plugin)
	}

	return plugins, nil
}

// LoadPluginsFromDirWithDefault loads plugins from .aegisgate-plugins/
// in the given root directory. Returns nil if the directory doesn't exist.
func LoadPluginsFromDirWithDefault(root string) ([]*YAMLPlugin, error) {
	pluginDir := filepath.Join(root, ".aegisgate-plugins")
	return LoadPluginsFromDir(pluginDir)
}

// ---------------------------------------------------------------------
// Plugin registration with detector engine
// ---------------------------------------------------------------------

// RegisterPluginsWithDetector converts plugin rules to detector PatternDef
// and registers them with the detector engine.
func RegisterPluginsWithDetector(plugins []*YAMLPlugin) error {
	var defs []detectors.PatternDef

	for _, p := range plugins {
		for _, rule := range p.config.Rules {
			defs = append(defs, detectors.PatternDef{
				Name:        rule.Name,
				Regex:       rule.Pattern,
				Severity:    parsePluginSeverity(rule.Severity),
				Category:    detectors.Category(rule.Category),
				Description: rule.Description,
			})
		}
	}

	if len(defs) > 0 {
		return detectors.RegisterCustomPatterns(defs)
	}
	return nil
}

// ---------------------------------------------------------------------
// YAML parsing (minimal, no external dependencies)
// ---------------------------------------------------------------------

// ParsePluginConfig parses YAML plugin configuration from bytes.
// This is a minimal YAML parser that handles the plugin format.
func ParsePluginConfig(data []byte) (*PluginConfig, error) {
	cfg := &PluginConfig{}
	lines := strings.Split(string(data), "\n")

	var currentRule *PluginRule

	for _, rawLine := range lines {
		// Strip comments.
		if idx := strings.Index(rawLine, "#"); idx >= 0 {
			beforeHash := rawLine[:idx]
			if !strings.Contains(beforeHash, "\"") || strings.Count(beforeHash, "\"")%2 == 0 {
				rawLine = beforeHash
			}
		}
		line := strings.TrimSpace(rawLine)

		if line == "" {
			continue
		}

		// Check for rule list item.
		if strings.HasPrefix(line, "- ") {
			rest := strings.TrimSpace(line[2:])

			// Finalize previous rule.
			if currentRule != nil {
				cfg.Rules = append(cfg.Rules, *currentRule)
			}
			currentRule = &PluginRule{}

			// Parse inline key:value on the list item.
			if rest != "" {
				parsePluginRuleKV(currentRule, rest)
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
		value = stripQuotes(value)

		// Top-level keys.
		if currentRule == nil {
			switch key {
			case "name":
				cfg.Name = value
			}
			continue
		}

		// Rule properties.
		parsePluginRuleKV(currentRule, line)
	}

	// Finalize last rule.
	if currentRule != nil {
		cfg.Rules = append(cfg.Rules, *currentRule)
	}

	if cfg.Name == "" {
		return nil, fmt.Errorf("plugin missing name")
	}

	return cfg, nil
}

// parsePluginRuleKV parses a key:value pair into a PluginRule.
func parsePluginRuleKV(rule *PluginRule, kv string) {
	idx := strings.Index(kv, ":")
	if idx < 0 {
		return
	}
	key := strings.TrimSpace(kv[:idx])
	value := strings.TrimSpace(kv[idx+1:])
	value = stripQuotes(value)

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

// stripQuotes removes surrounding quotes from a string.
func stripQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
