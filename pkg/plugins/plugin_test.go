// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Plugin System Tests
// =========================================================================
//
// Tests for YAML plugin loading, parsing, detection, and registration
// with the detector engine.
//
// =========================================================================

package plugins

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/detectors"
)

// ---------------------------------------------------------------------
// YAML parsing tests
// ---------------------------------------------------------------------

func TestParsePluginConfig_Basic(t *testing.T) {
	yaml := `name: my_detector
rules:
  - name: custom_key
    pattern: "my_key_[a-z0-9]+"
    severity: high
    category: secrets
    description: "Custom API key pattern"
`
	cfg, err := ParsePluginConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("ParsePluginConfig error: %v", err)
	}

	if cfg.Name != "my_detector" {
		t.Errorf("name = %s, want my_detector", cfg.Name)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}
	if cfg.Rules[0].Name != "custom_key" {
		t.Errorf("rule name = %s, want custom_key", cfg.Rules[0].Name)
	}
	if cfg.Rules[0].Pattern != "my_key_[a-z0-9]+" {
		t.Errorf("pattern = %s", cfg.Rules[0].Pattern)
	}
	if cfg.Rules[0].Severity != "high" {
		t.Errorf("severity = %s, want high", cfg.Rules[0].Severity)
	}
}

func TestParsePluginConfig_MultipleRules(t *testing.T) {
	yaml := `name: multi_detector
rules:
  - name: rule1
    pattern: "pattern1"
    severity: high
    category: secrets
  - name: rule2
    pattern: "pattern2"
    severity: medium
    category: pii
  - name: rule3
    pattern: "pattern3"
    severity: low
    category: compliance
`
	cfg, err := ParsePluginConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("ParsePluginConfig error: %v", err)
	}

	if len(cfg.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(cfg.Rules))
	}
	if cfg.Rules[2].Name != "rule3" {
		t.Errorf("third rule name = %s, want rule3", cfg.Rules[2].Name)
	}
}

func TestParsePluginConfig_MissingName(t *testing.T) {
	yaml := `rules:
  - name: test
    pattern: "test"
`
	_, err := ParsePluginConfig([]byte(yaml))
	if err == nil {
		t.Error("ParsePluginConfig should error on missing name")
	}
}

func TestParsePluginConfig_Comments(t *testing.T) {
	yaml := `# This is a comment
name: test_detector
# Another comment
rules:
  - name: rule1 # inline comment
    pattern: "test"
    severity: high
`
	cfg, err := ParsePluginConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("ParsePluginConfig error: %v", err)
	}
	if cfg.Name != "test_detector" {
		t.Errorf("name = %s, want test_detector", cfg.Name)
	}
}

func TestParsePluginConfig_Empty(t *testing.T) {
	_, err := ParsePluginConfig([]byte(""))
	if err == nil {
		t.Error("ParsePluginConfig should error on empty input")
	}
}

// ---------------------------------------------------------------------
// YAMLPlugin tests
// ---------------------------------------------------------------------

func TestYAMLPlugin_Detect(t *testing.T) {
	cfg := &PluginConfig{
		Name: "test_plugin",
		Rules: []PluginRule{
			{
				Name:     "custom_token",
				Pattern:  "tok_[a-z0-9]+",
				Severity: "high",
				Category: "secrets",
			},
		},
	}

	plugin := &YAMLPlugin{config: *cfg, name: cfg.Name}
	if err := plugin.Init(nil); err != nil {
		t.Fatalf("Init error: %v", err)
	}

	text := "line 1\nmy token is tok_abc123 here\nline 3"
	findings := plugin.Detect(text)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "custom_token" {
		t.Errorf("RuleID = %s, want custom_token", f.RuleID)
	}
	if f.Line != 2 {
		t.Errorf("Line = %d, want 2", f.Line)
	}
	if f.DetectionLayer != "plugin" {
		t.Errorf("DetectionLayer = %s, want plugin", f.DetectionLayer)
	}
}

func TestYAMLPlugin_Detect_NoMatch(t *testing.T) {
	cfg := &PluginConfig{
		Name: "test_plugin",
		Rules: []PluginRule{
			{
				Name:     "custom_token",
				Pattern:  "tok_[a-z0-9]+",
				Severity: "high",
				Category: "secrets",
			},
		},
	}

	plugin := &YAMLPlugin{config: *cfg, name: cfg.Name}
	plugin.Init(nil)

	findings := plugin.Detect("no matches here")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestYAMLPlugin_Detect_EmptyText(t *testing.T) {
	plugin := &YAMLPlugin{
		config: PluginConfig{Name: "test"},
		name:   "test",
	}
	plugin.Init(nil)

	findings := plugin.Detect("")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty text, got %d", len(findings))
	}
}

func TestYAMLPlugin_Name(t *testing.T) {
	plugin := &YAMLPlugin{name: "my_plugin"}
	if plugin.Name() != "my_plugin" {
		t.Errorf("Name() = %s, want my_plugin", plugin.Name())
	}
}

func TestYAMLPlugin_Init_WithNameOverride(t *testing.T) {
	plugin := &YAMLPlugin{
		config: PluginConfig{Name: "original"},
		name:   "original",
	}
	err := plugin.Init(map[string]string{"name": "overridden"})
	if err != nil {
		t.Fatalf("Init error: %v", err)
	}
	if plugin.Name() != "overridden" {
		t.Errorf("Name = %s, want overridden", plugin.Name())
	}
}

func TestYAMLPlugin_InvalidRegex(t *testing.T) {
	cfg := &PluginConfig{
		Name: "bad_plugin",
		Rules: []PluginRule{
			{
				Name:     "bad_rule",
				Pattern:  "[invalid",
				Severity: "high",
				Category: "secrets",
			},
		},
	}

	plugin := &YAMLPlugin{config: *cfg, name: cfg.Name}
	err := plugin.Init(nil)
	if err == nil {
		t.Error("Init should error on invalid regex")
	}
}

func TestYAMLPlugin_MissingPattern(t *testing.T) {
	cfg := &PluginConfig{
		Name: "bad_plugin",
		Rules: []PluginRule{
			{
				Name:     "no_pattern",
				Severity: "high",
				Category: "secrets",
			},
		},
	}

	plugin := &YAMLPlugin{config: *cfg, name: cfg.Name}
	err := plugin.Init(nil)
	if err == nil {
		t.Error("Init should error on missing pattern")
	}
}

func TestParsePluginSeverity(t *testing.T) {
	tests := []struct {
		input  string
		expect detectors.Severity
	}{
		{"critical", detectors.SeverityCritical},
		{"high", detectors.SeverityHigh},
		{"medium", detectors.SeverityMedium},
		{"low", detectors.SeverityLow},
		{"unknown", detectors.SeverityMedium},
		{"", detectors.SeverityMedium},
	}

	for _, tt := range tests {
		got := parsePluginSeverity(tt.input)
		if got != tt.expect {
			t.Errorf("parsePluginSeverity(%s) = %s, want %s", tt.input, got, tt.expect)
		}
	}
}

func TestYAMLPlugin_Rules(t *testing.T) {
	cfg := &PluginConfig{
		Name: "test",
		Rules: []PluginRule{
			{Name: "r1", Pattern: "p1", Severity: "high"},
		},
	}
	plugin := &YAMLPlugin{config: *cfg, name: cfg.Name}
	rules := plugin.Rules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Name != "r1" {
		t.Errorf("rule name = %s, want r1", rules[0].Name)
	}
}

// ---------------------------------------------------------------------
// File loading tests
// ---------------------------------------------------------------------

func TestLoadPlugin(t *testing.T) {
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, "custom.yaml")

	yaml := `name: file_detector
rules:
  - name: file_rule
    pattern: "secret_[0-9]+"
    severity: critical
    category: secrets
    description: "File-based rule"
`
	os.WriteFile(pluginPath, []byte(yaml), 0644)

	plugin, err := LoadPlugin(pluginPath)
	if err != nil {
		t.Fatalf("LoadPlugin error: %v", err)
	}

	if plugin.Name() != "file_detector" {
		t.Errorf("plugin name = %s, want file_detector", plugin.Name())
	}

	// Test detection.
	findings := plugin.Detect("found secret_12345 here")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "file_rule" {
		t.Errorf("RuleID = %s, want file_rule", findings[0].RuleID)
	}
}

func TestLoadPlugin_NonExistent(t *testing.T) {
	_, err := LoadPlugin("nonexistent.yaml")
	if err == nil {
		t.Error("LoadPlugin should error on non-existent file")
	}
}

func TestLoadPluginsFromDir(t *testing.T) {
	dir := t.TempDir()

	// Create two plugin files.
	yaml1 := `name: plugin1
rules:
  - name: rule1
    pattern: "pat1"
    severity: high
    category: secrets
`
	yaml2 := `name: plugin2
rules:
  - name: rule2
    pattern: "pat2"
    severity: medium
    category: pii
`
	os.WriteFile(filepath.Join(dir, "p1.yaml"), []byte(yaml1), 0644)
	os.WriteFile(filepath.Join(dir, "p2.yml"), []byte(yaml2), 0644)
	// Non-YAML file should be ignored.
	os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not a plugin"), 0644)

	plugins, err := LoadPluginsFromDir(dir)
	if err != nil {
		t.Fatalf("LoadPluginsFromDir error: %v", err)
	}

	if len(plugins) != 2 {
		t.Fatalf("expected 2 plugins, got %d", len(plugins))
	}
}

func TestLoadPluginsFromDir_NonExistent(t *testing.T) {
	plugins, err := LoadPluginsFromDir("nonexistent_dir_12345")
	if err != nil {
		t.Fatalf("LoadPluginsFromDir should not error on missing dir: %v", err)
	}
	if len(plugins) != 0 {
		t.Errorf("expected 0 plugins for missing dir, got %d", len(plugins))
	}
}

func TestLoadPluginsFromDirWithDefault(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, ".aegisgate-plugins")
	os.MkdirAll(pluginDir, 0755)

	yaml := `name: default_plugin
rules:
  - name: def_rule
    pattern: "def_[0-9]+"
    severity: low
    category: compliance
`
	os.WriteFile(filepath.Join(pluginDir, "plugin.yaml"), []byte(yaml), 0644)

	plugins, err := LoadPluginsFromDirWithDefault(dir)
	if err != nil {
		t.Fatalf("LoadPluginsFromDirWithDefault error: %v", err)
	}
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}
}

func TestLoadPluginsFromDirWithDefault_NoDir(t *testing.T) {
	plugins, err := LoadPluginsFromDirWithDefault(t.TempDir())
	if err != nil {
		t.Fatalf("should not error without plugin dir: %v", err)
	}
	if len(plugins) != 0 {
		t.Errorf("expected 0 plugins without dir, got %d", len(plugins))
	}
}

// ---------------------------------------------------------------------
// Registration tests
// ---------------------------------------------------------------------

func TestRegisterPluginsWithDetector(t *testing.T) {
	detectors.ResetCustomPatterns()
	defer detectors.ResetCustomPatterns()

	plugin := &YAMLPlugin{
		config: PluginConfig{
			Name: "reg_plugin",
			Rules: []PluginRule{
				{
					Name:     "reg_test_rule",
					Pattern:  "regtest_[a-z]+",
					Severity: "high",
					Category: "secrets",
				},
			},
		},
		name: "reg_plugin",
	}
	plugin.Init(nil)

	err := RegisterPluginsWithDetector([]*YAMLPlugin{plugin})
	if err != nil {
		t.Fatalf("RegisterPluginsWithDetector error: %v", err)
	}

	// Verify the custom pattern is registered.
	matches := detectors.DetectCustomPatterns("found regtest_abc here")
	if len(matches) == 0 {
		t.Error("registered plugin rule should be detected by DetectCustomPatterns")
	}
}

func TestRegisterPluginsWithDetector_Empty(t *testing.T) {
	err := RegisterPluginsWithDetector(nil)
	if err != nil {
		t.Errorf("RegisterPluginsWithDetector with nil should not error: %v", err)
	}
}
