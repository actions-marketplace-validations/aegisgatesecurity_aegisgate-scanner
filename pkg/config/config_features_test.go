// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Config New Features Tests
// =========================================================================

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-scanner/internal/detectors"
)

// ---------------------------------------------------------------------
// CustomRules validation tests
// ---------------------------------------------------------------------

func TestConfig_CustomRulesValidation_Valid(t *testing.T) {
	cfg := Default()
	cfg.CustomRules = []CustomRuleConfig{
		{Name: "custom_employee_id", Pattern: "EMP-\\d{6}", Severity: "medium", Category: "pii", Description: "Internal employee ID"},
		{Name: "custom_api_token", Pattern: "tok_[a-z0-9]{32}", Severity: "high", Category: "secrets", Description: "API token"},
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("expected validation to pass for valid custom rules, got error: %v", err)
	}
}

func TestConfig_CustomRulesValidation_NoName(t *testing.T) {
	cfg := Default()
	cfg.CustomRules = []CustomRuleConfig{
		{Name: "", Pattern: "EMP-\\d{6}", Severity: "medium"},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for rule without name, got nil")
	}
}

func TestConfig_CustomRulesValidation_NoPattern(t *testing.T) {
	cfg := Default()
	cfg.CustomRules = []CustomRuleConfig{
		{Name: "custom_rule", Pattern: "", Severity: "medium"},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for rule without pattern, got nil")
	}
}

func TestConfig_CustomRulesValidation_InvalidSeverity(t *testing.T) {
	cfg := Default()
	cfg.CustomRules = []CustomRuleConfig{
		{Name: "custom_rule", Pattern: "EMP-\\d{6}", Severity: "extreme"},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for invalid severity, got nil")
	}
}

// ---------------------------------------------------------------------
// FailOnSeverity validation tests
// ---------------------------------------------------------------------

func TestConfig_FailOnSeverity_Valid(t *testing.T) {
	for _, sev := range []string{"critical", "high", "medium", "low", ""} {
		cfg := Default()
		cfg.FailOnSeverity = sev
		if err := cfg.Validate(); err != nil {
			t.Errorf("expected validation to pass for fail_on_severity=%q, got error: %v", sev, err)
		}
	}
}

func TestConfig_FailOnSeverity_Invalid(t *testing.T) {
	cfg := Default()
	cfg.FailOnSeverity = "extreme"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for invalid fail_on_severity, got nil")
	}
}

// ---------------------------------------------------------------------
// ToDetectorPatterns tests
// ---------------------------------------------------------------------

func TestConfig_ToDetectorPatterns(t *testing.T) {
	cfg := Default()
	cfg.CustomRules = []CustomRuleConfig{
		{Name: "custom_employee_id", Pattern: "EMP-\\d{6}", Severity: "medium", Category: "pii", Description: "Internal employee ID"},
		{Name: "custom_api_token", Pattern: "tok_[a-z0-9]{32}", Severity: "high", Category: "secrets", Description: "API token"},
	}

	defs := cfg.ToDetectorPatterns()
	if len(defs) != 2 {
		t.Fatalf("expected 2 pattern defs, got %d", len(defs))
	}

	if defs[0].Name != "custom_employee_id" {
		t.Errorf("defs[0] Name = %s, want custom_employee_id", defs[0].Name)
	}
	if defs[0].Regex != "EMP-\\d{6}" {
		t.Errorf("defs[0] Regex = %s, want EMP-\\d{6}", defs[0].Regex)
	}
	if defs[0].Severity != detectors.SeverityMedium {
		t.Errorf("defs[0] Severity = %s, want %s", defs[0].Severity, detectors.SeverityMedium)
	}
	if defs[0].Category != detectors.Category("pii") {
		t.Errorf("defs[0] Category = %s, want pii", defs[0].Category)
	}
	if defs[0].Description != "Internal employee ID" {
		t.Errorf("defs[0] Description = %s, want 'Internal employee ID'", defs[0].Description)
	}

	if defs[1].Name != "custom_api_token" {
		t.Errorf("defs[1] Name = %s, want custom_api_token", defs[1].Name)
	}
	if defs[1].Severity != detectors.SeverityHigh {
		t.Errorf("defs[1] Severity = %s, want %s", defs[1].Severity, detectors.SeverityHigh)
	}
}

func TestConfig_ToDetectorPatterns_Empty(t *testing.T) {
	cfg := Default()
	defs := cfg.ToDetectorPatterns()
	if defs != nil {
		t.Errorf("expected nil for no custom rules, got %v", defs)
	}
}

// ---------------------------------------------------------------------
// Default tests
// ---------------------------------------------------------------------

func TestConfig_Default_HasNewFields(t *testing.T) {
	cfg := Default()

	if !cfg.RespectGitIgnore {
		t.Error("expected RespectGitIgnore=true by default")
	}
	if cfg.FailOnSeverity != "low" {
		t.Errorf("expected FailOnSeverity='low' by default, got %q", cfg.FailOnSeverity)
	}
	if cfg.BaselinePath != "" {
		t.Errorf("expected BaselinePath='' by default, got %q", cfg.BaselinePath)
	}
	if cfg.CustomRules != nil {
		t.Errorf("expected CustomRules=nil by default, got %v", cfg.CustomRules)
	}
	if len(cfg.DisableRules) != 0 {
		t.Errorf("expected DisableRules empty by default, got %v", cfg.DisableRules)
	}
}

// ---------------------------------------------------------------------
// ToWalkOptions tests
// ---------------------------------------------------------------------

func TestConfig_ToWalkOptions_HasGitIgnore(t *testing.T) {
	cfg := Default()
	cfg.RespectGitIgnore = true
	cfg.IgnorePaths = []string{"vendor/", "*.tmp"}
	cfg.MaxFileSize = 1024

	opts := cfg.ToWalkOptions("/scan/root")

	if !opts.RespectGitIgnore {
		t.Error("expected RespectGitIgnore=true in WalkOptions")
	}
	if opts.Root != "/scan/root" {
		t.Errorf("expected Root=/scan/root, got %s", opts.Root)
	}
	if len(opts.IgnorePaths) != 2 {
		t.Errorf("expected 2 ignore paths, got %d", len(opts.IgnorePaths))
	}
	if opts.MaxFileSize != 1024 {
		t.Errorf("expected MaxFileSize=1024, got %d", opts.MaxFileSize)
	}

	// Also test when RespectGitIgnore is false.
	cfg.RespectGitIgnore = false
	opts = cfg.ToWalkOptions("/scan/root")
	if opts.RespectGitIgnore {
		t.Error("expected RespectGitIgnore=false in WalkOptions when disabled")
	}
}

// ---------------------------------------------------------------------
// ToScanOptions tests
// ---------------------------------------------------------------------

func TestConfig_ToScanOptions_HasDisableRules(t *testing.T) {
	cfg := Default()
	cfg.DisableRules = []string{"xss_script_tag", "pii_ssn"}
	cfg.MinSeverity = "high"

	opts := cfg.ToScanOptions()

	if len(opts.DisableRules) != 2 {
		t.Fatalf("expected 2 disabled rules, got %d", len(opts.DisableRules))
	}
	if opts.DisableRules[0] != "xss_script_tag" {
		t.Errorf("DisableRules[0] = %s, want xss_script_tag", opts.DisableRules[0])
	}
	if opts.DisableRules[1] != "pii_ssn" {
		t.Errorf("DisableRules[1] = %s, want pii_ssn", opts.DisableRules[1])
	}
	if opts.MinSeverity != detectors.SeverityHigh {
		t.Errorf("MinSeverity = %s, want %s", opts.MinSeverity, detectors.SeverityHigh)
	}
}

// ---------------------------------------------------------------------
// YAML parsing tests
// ---------------------------------------------------------------------

func TestConfig_CustomRulesFromYAML(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `custom_rules:
  - name: custom_employee_id
    pattern: 'EMP-\d{6}'
    severity: medium
    category: pii
    description: 'Internal employee ID'
  - name: custom_api_token
    pattern: 'tok_[a-z0-9]{32}'
    severity: high
    category: secrets
    description: 'API token'
fail_on_severity: high
disable_rules:
  - xss_script_tag
  - pii_ssn
`
	configPath := filepath.Join(dir, ".aegisgate.yml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	// Verify custom rules loaded.
	if len(cfg.CustomRules) != 2 {
		t.Fatalf("expected 2 custom rules, got %d", len(cfg.CustomRules))
	}
	if cfg.CustomRules[0].Name != "custom_employee_id" {
		t.Errorf("CustomRules[0] Name = %s, want custom_employee_id", cfg.CustomRules[0].Name)
	}
	if cfg.CustomRules[0].Pattern != "EMP-\\d{6}" {
		t.Errorf("CustomRules[0] Pattern = %s, want EMP-\\d{6}", cfg.CustomRules[0].Pattern)
	}
	if cfg.CustomRules[0].Severity != "medium" {
		t.Errorf("CustomRules[0] Severity = %s, want medium", cfg.CustomRules[0].Severity)
	}
	if cfg.CustomRules[0].Category != "pii" {
		t.Errorf("CustomRules[0] Category = %s, want pii", cfg.CustomRules[0].Category)
	}
	if cfg.CustomRules[0].Description != "Internal employee ID" {
		t.Errorf("CustomRules[0] Description = %s, want 'Internal employee ID'", cfg.CustomRules[0].Description)
	}
	if cfg.CustomRules[1].Name != "custom_api_token" {
		t.Errorf("CustomRules[1] Name = %s, want custom_api_token", cfg.CustomRules[1].Name)
	}
	if cfg.CustomRules[1].Severity != "high" {
		t.Errorf("CustomRules[1] Severity = %s, want high", cfg.CustomRules[1].Severity)
	}

	// Verify fail_on_severity loaded.
	if cfg.FailOnSeverity != "high" {
		t.Errorf("FailOnSeverity = %s, want high", cfg.FailOnSeverity)
	}

	// Verify disable_rules loaded.
	if len(cfg.DisableRules) != 2 {
		t.Fatalf("expected 2 disabled rules, got %d", len(cfg.DisableRules))
	}
	if cfg.DisableRules[0] != "xss_script_tag" {
		t.Errorf("DisableRules[0] = %s, want xss_script_tag", cfg.DisableRules[0])
	}
	if cfg.DisableRules[1] != "pii_ssn" {
		t.Errorf("DisableRules[1] = %s, want pii_ssn", cfg.DisableRules[1])
	}
}

// ---------------------------------------------------------------------
// Bonus: YAML with baseline_path and respect_gitignore (extra coverage)
// ---------------------------------------------------------------------

func TestConfig_YAML_BaselineAndGitIgnore(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `baseline_path: /path/to/baseline.json
respect_gitignore: false
fail_on_severity: critical
`
	configPath := filepath.Join(dir, ".aegisgate.yml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.BaselinePath != "/path/to/baseline.json" {
		t.Errorf("BaselinePath = %s, want /path/to/baseline.json", cfg.BaselinePath)
	}
	if cfg.RespectGitIgnore {
		t.Error("expected RespectGitIgnore=false")
	}
	if cfg.FailOnSeverity != "critical" {
		t.Errorf("FailOnSeverity = %s, want critical", cfg.FailOnSeverity)
	}
}

// ---------------------------------------------------------------------
// Bonus: YAML with inline disable_rules list (extra coverage)
// ---------------------------------------------------------------------

func TestConfig_YAML_InlineDisableRules(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `disable_rules: [xss_script_tag, pii_ssn]
`
	configPath := filepath.Join(dir, ".aegisgate.yml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if len(cfg.DisableRules) != 2 {
		t.Fatalf("expected 2 disabled rules, got %d", len(cfg.DisableRules))
	}
}

// ---------------------------------------------------------------------
// Bonus: ToDetectorPatterns with empty severity (extra coverage)
// ---------------------------------------------------------------------

func TestConfig_ToDetectorPatterns_EmptySeverity(t *testing.T) {
	cfg := Default()
	cfg.CustomRules = []CustomRuleConfig{
		{Name: "test_rule", Pattern: "test\\d+", Severity: "", Category: "test"},
	}

	defs := cfg.ToDetectorPatterns()
	if len(defs) != 1 {
		t.Fatalf("expected 1 pattern def, got %d", len(defs))
	}
	if defs[0].Severity != "" {
		t.Errorf("expected empty severity, got %s", defs[0].Severity)
	}
}

// ---------------------------------------------------------------------
// Bonus: Validate with multiple custom rules, one invalid (extra coverage)
// ---------------------------------------------------------------------

func TestConfig_CustomRulesValidation_MultipleOneInvalid(t *testing.T) {
	cfg := Default()
	cfg.CustomRules = []CustomRuleConfig{
		{Name: "valid_rule", Pattern: "test\\d+", Severity: "low"},
		{Name: "invalid_rule", Pattern: "test\\d+", Severity: "banana"},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for second rule with invalid severity, got nil")
	}
}

// ---------------------------------------------------------------------
// Bonus: ToScanOptions with no disabled rules (extra coverage)
// ---------------------------------------------------------------------

func TestConfig_ToScanOptions_NoDisableRules(t *testing.T) {
	cfg := Default()
	opts := cfg.ToScanOptions()

	if len(opts.DisableRules) != 0 {
		t.Errorf("expected 0 disabled rules, got %d", len(opts.DisableRules))
	}
}

// ---------------------------------------------------------------------
// Bonus: ToWalkOptions default values (extra coverage)
// ---------------------------------------------------------------------

func TestConfig_ToWalkOptions_Defaults(t *testing.T) {
	cfg := Default()
	opts := cfg.ToWalkOptions("/root")

	if !opts.RespectGitIgnore {
		t.Error("expected default RespectGitIgnore=true in WalkOptions")
	}
	if opts.Root != "/root" {
		t.Errorf("expected Root=/root, got %s", opts.Root)
	}
	if opts.MaxFileSize != 10*1024*1024 {
		t.Errorf("expected MaxFileSize=10MB, got %d", opts.MaxFileSize)
	}
}
