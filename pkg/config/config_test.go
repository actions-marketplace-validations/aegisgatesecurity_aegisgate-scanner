// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Configuration Tests
// =========================================================================
//
// Comprehensive tests for the config package covering:
//   - Default() values
//   - Load() from .aegisgate.yml, alt config names, defaults when no file
//   - Validate() for valid and invalid configs
//   - ToWalkOptions() conversion
//   - ToScanOptions() conversion
//   - parseYAML() for scalars, inline lists, block lists, comments, quotes
//   - Helper functions: parseInlineList, unquote, parseBool, parseInt64,
//     parseInt, parseFloat64, parseSeverity, findConfigFile
//
// =========================================================================

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/detectors"
)

// ---------------------------------------------------------------------
// Default()
// ---------------------------------------------------------------------

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg == nil {
		t.Fatal("Default() returned nil")
	}
	if len(cfg.IgnorePaths) != 0 {
		t.Errorf("IgnorePaths = %v, want empty slice", cfg.IgnorePaths)
	}
	if len(cfg.Extensions) != 0 {
		t.Errorf("Extensions = %v, want empty slice", cfg.Extensions)
	}
	if cfg.MaxFileSize != 10*1024*1024 {
		t.Errorf("MaxFileSize = %d, want %d", cfg.MaxFileSize, 10*1024*1024)
	}
	if cfg.FollowSymlinks != false {
		t.Errorf("FollowSymlinks = %v, want false", cfg.FollowSymlinks)
	}
	if cfg.MinSeverity != "low" {
		t.Errorf("MinSeverity = %q, want %q", cfg.MinSeverity, "low")
	}
	if cfg.EnableML != true {
		t.Errorf("EnableML = %v, want true", cfg.EnableML)
	}
	if cfg.MLThreshold != 0.50 {
		t.Errorf("MLThreshold = %f, want 0.50", cfg.MLThreshold)
	}
	if cfg.MaxFindingsPerFile != 0 {
		t.Errorf("MaxFindingsPerFile = %d, want 0", cfg.MaxFindingsPerFile)
	}
	if cfg.OutputFormat != "text" {
		t.Errorf("OutputFormat = %q, want %q", cfg.OutputFormat, "text")
	}
	if cfg.ColorOutput != true {
		t.Errorf("ColorOutput = %v, want true", cfg.ColorOutput)
	}
	if cfg.ModelPath != "" {
		t.Errorf("ModelPath = %q, want empty", cfg.ModelPath)
	}
}

// ---------------------------------------------------------------------
// Load()
// ---------------------------------------------------------------------

func TestLoad_NoConfigFile_ReturnsDefaults(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil")
	}
	if cfg.MinSeverity != "low" {
		t.Errorf("MinSeverity = %q, want %q (default)", cfg.MinSeverity, "low")
	}
	if cfg.OutputFormat != "text" {
		t.Errorf("OutputFormat = %q, want %q (default)", cfg.OutputFormat, "text")
	}
	if cfg.EnableML != true {
		t.Errorf("EnableML = %v, want true (default)", cfg.EnableML)
	}
}

func TestLoad_PrimaryConfigFile(t *testing.T) {
	dir := t.TempDir()
	content := `# AegisGate config
min_severity: high
output_format: json
enable_ml: false
ml_threshold: 0.75
max_file_size: 5242880
max_findings_per_file: 50
follow_symlinks: true
color_output: false
model_path: /path/to/model.onnx
ignore_paths:
  - vendor/
  - "*.git*"
extensions:
  - .py
  - .js
  - .go
`
	path := filepath.Join(dir, ".aegisgate.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.MinSeverity != "high" {
		t.Errorf("MinSeverity = %q, want %q", cfg.MinSeverity, "high")
	}
	if cfg.OutputFormat != "json" {
		t.Errorf("OutputFormat = %q, want %q", cfg.OutputFormat, "json")
	}
	if cfg.EnableML != false {
		t.Errorf("EnableML = %v, want false", cfg.EnableML)
	}
	if cfg.MLThreshold != 0.75 {
		t.Errorf("MLThreshold = %f, want 0.75", cfg.MLThreshold)
	}
	if cfg.MaxFileSize != 5242880 {
		t.Errorf("MaxFileSize = %d, want 5242880", cfg.MaxFileSize)
	}
	if cfg.MaxFindingsPerFile != 50 {
		t.Errorf("MaxFindingsPerFile = %d, want 50", cfg.MaxFindingsPerFile)
	}
	if cfg.FollowSymlinks != true {
		t.Errorf("FollowSymlinks = %v, want true", cfg.FollowSymlinks)
	}
	if cfg.ColorOutput != false {
		t.Errorf("ColorOutput = %v, want false", cfg.ColorOutput)
	}
	if cfg.ModelPath != "/path/to/model.onnx" {
		t.Errorf("ModelPath = %q, want %q", cfg.ModelPath, "/path/to/model.onnx")
	}
	if len(cfg.IgnorePaths) != 2 {
		t.Fatalf("IgnorePaths len = %d, want 2", len(cfg.IgnorePaths))
	}
	if cfg.IgnorePaths[0] != "vendor/" {
		t.Errorf("IgnorePaths[0] = %q, want %q", cfg.IgnorePaths[0], "vendor/")
	}
	if cfg.IgnorePaths[1] != "*.git*" {
		t.Errorf("IgnorePaths[1] = %q, want %q", cfg.IgnorePaths[1], "*.git*")
	}
	if len(cfg.Extensions) != 3 {
		t.Fatalf("Extensions len = %d, want 3", len(cfg.Extensions))
	}
	if cfg.Extensions[0] != ".py" {
		t.Errorf("Extensions[0] = %q, want %q", cfg.Extensions[0], ".py")
	}
	if cfg.Extensions[1] != ".js" {
		t.Errorf("Extensions[1] = %q, want %q", cfg.Extensions[1], ".js")
	}
	if cfg.Extensions[2] != ".go" {
		t.Errorf("Extensions[2] = %q, want %q", cfg.Extensions[2], ".go")
	}
}

func TestLoad_AltConfigFile_YAML_Extension(t *testing.T) {
	dir := t.TempDir()
	content := `min_severity: critical
output_format: sarif
`
	// Use .yaml instead of .yml
	path := filepath.Join(dir, ".aegisgate.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.MinSeverity != "critical" {
		t.Errorf("MinSeverity = %q, want %q", cfg.MinSeverity, "critical")
	}
	if cfg.OutputFormat != "sarif" {
		t.Errorf("OutputFormat = %q, want %q", cfg.OutputFormat, "sarif")
	}
}

func TestLoad_AltConfigFile_ScannerName(t *testing.T) {
	dir := t.TempDir()
	content := `min_severity: medium
output_format: text
`
	path := filepath.Join(dir, ".aegisgate-scanner.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.MinSeverity != "medium" {
		t.Errorf("MinSeverity = %q, want %q", cfg.MinSeverity, "medium")
	}
}

func TestLoad_AltConfigFile_ScannerNameYAML(t *testing.T) {
	dir := t.TempDir()
	content := `min_severity: high
output_format: json
`
	path := filepath.Join(dir, ".aegisgate-scanner.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.MinSeverity != "high" {
		t.Errorf("MinSeverity = %q, want %q", cfg.MinSeverity, "high")
	}
	if cfg.OutputFormat != "json" {
		t.Errorf("OutputFormat = %q, want %q", cfg.OutputFormat, "json")
	}
}

func TestLoad_InvalidConfig_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	content := `min_severity: bogus
`
	path := filepath.Join(dir, ".aegisgate.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(dir)
	if err == nil {
		t.Fatal("Load() expected error for invalid config, got nil")
	}
	if cfg != nil {
		t.Errorf("Load() expected nil config on error, got %+v", cfg)
	}
}

func TestLoad_PartialConfig_MergesWithDefaults(t *testing.T) {
	dir := t.TempDir()
	content := `min_severity: critical
`
	path := filepath.Join(dir, ".aegisgate.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	// Overridden value
	if cfg.MinSeverity != "critical" {
		t.Errorf("MinSeverity = %q, want %q", cfg.MinSeverity, "critical")
	}
	// Default value should remain
	if cfg.OutputFormat != "text" {
		t.Errorf("OutputFormat = %q, want %q (default)", cfg.OutputFormat, "text")
	}
	if cfg.EnableML != true {
		t.Errorf("EnableML = %v, want true (default)", cfg.EnableML)
	}
	if cfg.MaxFileSize != 10*1024*1024 {
		t.Errorf("MaxFileSize = %d, want %d (default)", cfg.MaxFileSize, 10*1024*1024)
	}
}

func TestLoad_InlineListConfig(t *testing.T) {
	dir := t.TempDir()
	content := `ignore_paths: [vendor/, "*.git*", node_modules/]
extensions: [.py, .js, .go]
`
	path := filepath.Join(dir, ".aegisgate.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(cfg.IgnorePaths) != 3 {
		t.Fatalf("IgnorePaths len = %d, want 3", len(cfg.IgnorePaths))
	}
	if cfg.IgnorePaths[0] != "vendor/" {
		t.Errorf("IgnorePaths[0] = %q, want %q", cfg.IgnorePaths[0], "vendor/")
	}
	if cfg.IgnorePaths[1] != "*.git*" {
		t.Errorf("IgnorePaths[1] = %q, want %q", cfg.IgnorePaths[1], "*.git*")
	}
	if cfg.IgnorePaths[2] != "node_modules/" {
		t.Errorf("IgnorePaths[2] = %q, want %q", cfg.IgnorePaths[2], "node_modules/")
	}
	if len(cfg.Extensions) != 3 {
		t.Fatalf("Extensions len = %d, want 3", len(cfg.Extensions))
	}
	if cfg.Extensions[0] != ".py" {
		t.Errorf("Extensions[0] = %q, want %q", cfg.Extensions[0], ".py")
	}
}

// ---------------------------------------------------------------------
// findConfigFile()
// ---------------------------------------------------------------------

func TestFindConfigFile_Primary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".aegisgate.yml")
	if err := os.WriteFile(path, []byte("min_severity: low\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result := findConfigFile(dir)
	if result != path {
		t.Errorf("findConfigFile() = %q, want %q", result, path)
	}
}

func TestFindConfigFile_AltYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".aegisgate.yaml")
	if err := os.WriteFile(path, []byte("min_severity: low\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result := findConfigFile(dir)
	if result != path {
		t.Errorf("findConfigFile() = %q, want %q", result, path)
	}
}

func TestFindConfigFile_ScannerName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".aegisgate-scanner.yml")
	if err := os.WriteFile(path, []byte("min_severity: low\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result := findConfigFile(dir)
	if result != path {
		t.Errorf("findConfigFile() = %q, want %q", result, path)
	}
}

func TestFindConfigFile_ScannerNameYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".aegisgate-scanner.yaml")
	if err := os.WriteFile(path, []byte("min_severity: low\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result := findConfigFile(dir)
	if result != path {
		t.Errorf("findConfigFile() = %q, want %q", result, path)
	}
}

func TestFindConfigFile_NoneFound(t *testing.T) {
	dir := t.TempDir()
	result := findConfigFile(dir)
	if result != "" {
		t.Errorf("findConfigFile() = %q, want empty string", result)
	}
}

func TestFindConfigFile_PriorityOrder(t *testing.T) {
	dir := t.TempDir()
	// Create both .yml and .yaml — .yml should be found first (first in altConfigFileNames)
	ymlPath := filepath.Join(dir, ".aegisgate.yml")
	yamlPath := filepath.Join(dir, ".aegisgate.yaml")
	if err := os.WriteFile(ymlPath, []byte("min_severity: low\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(yamlPath, []byte("min_severity: low\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	result := findConfigFile(dir)
	if result != ymlPath {
		t.Errorf("findConfigFile() = %q, want %q (priority)", result, ymlPath)
	}
}

// ---------------------------------------------------------------------
// Validate()
// ---------------------------------------------------------------------

func TestValidate_DefaultConfig_Passes(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Errorf("Default config Validate() error: %v", err)
	}
}

func TestValidate_ValidSeverities(t *testing.T) {
	severities := []string{"critical", "high", "medium", "low", "", "CRITICAL", "High", "MEDIUM"}
	for _, s := range severities {
		cfg := Default()
		cfg.MinSeverity = s
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() with MinSeverity=%q error: %v", s, err)
		}
	}
}

func TestValidate_InvalidSeverity(t *testing.T) {
	cfg := Default()
	cfg.MinSeverity = "bogus"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error for invalid min_severity, got nil")
	}
}

func TestValidate_InvalidSeverity_ErrorContains(t *testing.T) {
	cfg := Default()
	cfg.MinSeverity = "ultra"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error, got nil")
	}
	if !contains(err.Error(), "invalid min_severity") {
		t.Errorf("Validate() error = %q, want it to contain 'invalid min_severity'", err.Error())
	}
}

func TestValidate_ValidOutputFormats(t *testing.T) {
	formats := []string{"sarif", "json", "text", "", "SARIF", "Json", "TEXT"}
	for _, f := range formats {
		cfg := Default()
		cfg.OutputFormat = f
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() with OutputFormat=%q error: %v", f, err)
		}
	}
}

func TestValidate_InvalidOutputFormat(t *testing.T) {
	cfg := Default()
	cfg.OutputFormat = "xml"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error for invalid output_format, got nil")
	}
	if !contains(err.Error(), "invalid output_format") {
		t.Errorf("Validate() error = %q, want it to contain 'invalid output_format'", err.Error())
	}
}

func TestValidate_ValidMLThresholds(t *testing.T) {
	thresholds := []float64{0, 0.1, 0.25, 0.5, 0.75, 0.99, 1.0}
	for _, th := range thresholds {
		cfg := Default()
		cfg.MLThreshold = th
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() with MLThreshold=%f error: %v", th, err)
		}
	}
}

func TestValidate_NegativeMLThreshold(t *testing.T) {
	cfg := Default()
	cfg.MLThreshold = -0.01
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error for negative ml_threshold, got nil")
	}
	if !contains(err.Error(), "invalid ml_threshold") {
		t.Errorf("Validate() error = %q, want it to contain 'invalid ml_threshold'", err.Error())
	}
}

func TestValidate_MLThresholdAboveOne(t *testing.T) {
	cfg := Default()
	cfg.MLThreshold = 1.01
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error for ml_threshold > 1, got nil")
	}
}

func TestValidate_ValidMaxFileSize(t *testing.T) {
	sizes := []int64{0, 1, 1024, 1048576, 10 * 1024 * 1024}
	for _, s := range sizes {
		cfg := Default()
		cfg.MaxFileSize = s
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() with MaxFileSize=%d error: %v", s, err)
		}
	}
}

func TestValidate_NegativeMaxFileSize(t *testing.T) {
	cfg := Default()
	cfg.MaxFileSize = -1
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error for negative max_file_size, got nil")
	}
	if !contains(err.Error(), "invalid max_file_size") {
		t.Errorf("Validate() error = %q, want it to contain 'invalid max_file_size'", err.Error())
	}
}

// ---------------------------------------------------------------------
// ToWalkOptions()
// ---------------------------------------------------------------------

func TestToWalkOptions(t *testing.T) {
	cfg := &Config{
		IgnorePaths:    []string{"vendor/", "*.git*"},
		MaxFileSize:    5242880,
		FollowSymlinks: true,
		Extensions:     []string{".py", ".js"},
	}

	opts := cfg.ToWalkOptions("/scan/root")

	if opts.Root != "/scan/root" {
		t.Errorf("Root = %q, want %q", opts.Root, "/scan/root")
	}
	if len(opts.IgnorePaths) != 2 {
		t.Fatalf("IgnorePaths len = %d, want 2", len(opts.IgnorePaths))
	}
	if opts.IgnorePaths[0] != "vendor/" {
		t.Errorf("IgnorePaths[0] = %q, want %q", opts.IgnorePaths[0], "vendor/")
	}
	if opts.IgnorePaths[1] != "*.git*" {
		t.Errorf("IgnorePaths[1] = %q, want %q", opts.IgnorePaths[1], "*.git*")
	}
	if opts.MaxFileSize != 5242880 {
		t.Errorf("MaxFileSize = %d, want 5242880", opts.MaxFileSize)
	}
	if opts.FollowSymlinks != true {
		t.Errorf("FollowSymlinks = %v, want true", opts.FollowSymlinks)
	}
	if len(opts.Extensions) != 2 {
		t.Fatalf("Extensions len = %d, want 2", len(opts.Extensions))
	}
	if opts.Extensions[0] != ".py" {
		t.Errorf("Extensions[0] = %q, want %q", opts.Extensions[0], ".py")
	}
	if opts.Extensions[1] != ".js" {
		t.Errorf("Extensions[1] = %q, want %q", opts.Extensions[1], ".js")
	}
}

func TestToWalkOptions_DefaultConfig(t *testing.T) {
	cfg := Default()
	opts := cfg.ToWalkOptions("/root")

	if opts.Root != "/root" {
		t.Errorf("Root = %q, want %q", opts.Root, "/root")
	}
	if opts.MaxFileSize != 10*1024*1024 {
		t.Errorf("MaxFileSize = %d, want %d", opts.MaxFileSize, 10*1024*1024)
	}
	if opts.FollowSymlinks != false {
		t.Errorf("FollowSymlinks = %v, want false", opts.FollowSymlinks)
	}
	if len(opts.IgnorePaths) != 0 {
		t.Errorf("IgnorePaths len = %d, want 0", len(opts.IgnorePaths))
	}
	if len(opts.Extensions) != 0 {
		t.Errorf("Extensions len = %d, want 0", len(opts.Extensions))
	}
}

// ---------------------------------------------------------------------
// ToScanOptions()
// ---------------------------------------------------------------------

func TestToScanOptions(t *testing.T) {
	cfg := &Config{
		EnableML:           true,
		MLThreshold:        0.85,
		MinSeverity:        "high",
		MaxFindingsPerFile: 100,
	}

	opts := cfg.ToScanOptions()

	if opts.EnableML != true {
		t.Errorf("EnableML = %v, want true", opts.EnableML)
	}
	if opts.MLThreshold != 0.85 {
		t.Errorf("MLThreshold = %f, want 0.85", opts.MLThreshold)
	}
	if opts.MinSeverity != detectors.SeverityHigh {
		t.Errorf("MinSeverity = %q, want %q", opts.MinSeverity, detectors.SeverityHigh)
	}
	if opts.MaxFindingsPerFile != 100 {
		t.Errorf("MaxFindingsPerFile = %d, want 100", opts.MaxFindingsPerFile)
	}
}

func TestToScanOptions_DefaultConfig(t *testing.T) {
	cfg := Default()
	opts := cfg.ToScanOptions()

	if opts.EnableML != true {
		t.Errorf("EnableML = %v, want true", opts.EnableML)
	}
	if opts.MLThreshold != 0.50 {
		t.Errorf("MLThreshold = %f, want 0.50", opts.MLThreshold)
	}
	if opts.MinSeverity != detectors.SeverityLow {
		t.Errorf("MinSeverity = %q, want %q", opts.MinSeverity, detectors.SeverityLow)
	}
	if opts.MaxFindingsPerFile != 0 {
		t.Errorf("MaxFindingsPerFile = %d, want 0", opts.MaxFindingsPerFile)
	}
}

// ---------------------------------------------------------------------
// parseSeverity()
// ---------------------------------------------------------------------

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  detectors.Severity
	}{
		{"critical", detectors.SeverityCritical},
		{"high", detectors.SeverityHigh},
		{"medium", detectors.SeverityMedium},
		{"low", detectors.SeverityLow},
		{"CRITICAL", detectors.SeverityCritical},
		{"HIGH", detectors.SeverityHigh},
		{"Medium", detectors.SeverityMedium},
		{"LOW", detectors.SeverityLow},
		{"", ""},
		{"unknown", ""},
		{"bogus", ""},
	}
	for _, tc := range tests {
		got := parseSeverity(tc.input)
		if got != tc.want {
			t.Errorf("parseSeverity(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------
// parseYAML()
// ---------------------------------------------------------------------

func TestParseYAML_ScalarValues(t *testing.T) {
	data := []byte(`min_severity: high
output_format: sarif
enable_ml: false
ml_threshold: 0.75
max_file_size: 1048576
max_findings_per_file: 25
follow_symlinks: true
color_output: false
model_path: /models/model.onnx
`)
	cfg := Default()
	if err := parseYAML(data, cfg); err != nil {
		t.Fatalf("parseYAML() error: %v", err)
	}
	if cfg.MinSeverity != "high" {
		t.Errorf("MinSeverity = %q, want %q", cfg.MinSeverity, "high")
	}
	if cfg.OutputFormat != "sarif" {
		t.Errorf("OutputFormat = %q, want %q", cfg.OutputFormat, "sarif")
	}
	if cfg.EnableML != false {
		t.Errorf("EnableML = %v, want false", cfg.EnableML)
	}
	if cfg.MLThreshold != 0.75 {
		t.Errorf("MLThreshold = %f, want 0.75", cfg.MLThreshold)
	}
	if cfg.MaxFileSize != 1048576 {
		t.Errorf("MaxFileSize = %d, want 1048576", cfg.MaxFileSize)
	}
	if cfg.MaxFindingsPerFile != 25 {
		t.Errorf("MaxFindingsPerFile = %d, want 25", cfg.MaxFindingsPerFile)
	}
	if cfg.FollowSymlinks != true {
		t.Errorf("FollowSymlinks = %v, want true", cfg.FollowSymlinks)
	}
	if cfg.ColorOutput != false {
		t.Errorf("ColorOutput = %v, want false", cfg.ColorOutput)
	}
	if cfg.ModelPath != "/models/model.onnx" {
		t.Errorf("ModelPath = %q, want %q", cfg.ModelPath, "/models/model.onnx")
	}
}

func TestParseYAML_InlineList(t *testing.T) {
	data := []byte(`ignore_paths: [vendor/, "*.git*", node_modules/]
extensions: [.py, .js, .go, .rb]
`)
	cfg := Default()
	if err := parseYAML(data, cfg); err != nil {
		t.Fatalf("parseYAML() error: %v", err)
	}
	if len(cfg.IgnorePaths) != 3 {
		t.Fatalf("IgnorePaths len = %d, want 3", len(cfg.IgnorePaths))
	}
	if cfg.IgnorePaths[0] != "vendor/" {
		t.Errorf("IgnorePaths[0] = %q, want %q", cfg.IgnorePaths[0], "vendor/")
	}
	if cfg.IgnorePaths[1] != "*.git*" {
		t.Errorf("IgnorePaths[1] = %q, want %q", cfg.IgnorePaths[1], "*.git*")
	}
	if cfg.IgnorePaths[2] != "node_modules/" {
		t.Errorf("IgnorePaths[2] = %q, want %q", cfg.IgnorePaths[2], "node_modules/")
	}
	if len(cfg.Extensions) != 4 {
		t.Fatalf("Extensions len = %d, want 4", len(cfg.Extensions))
	}
	if cfg.Extensions[0] != ".py" {
		t.Errorf("Extensions[0] = %q, want %q", cfg.Extensions[0], ".py")
	}
	if cfg.Extensions[3] != ".rb" {
		t.Errorf("Extensions[3] = %q, want %q", cfg.Extensions[3], ".rb")
	}
}

func TestParseYAML_BlockList(t *testing.T) {
	data := []byte(`ignore_paths:
  - vendor/
  - "*.git*"
  - node_modules/
extensions:
  - .py
  - .js
`)
	cfg := Default()
	if err := parseYAML(data, cfg); err != nil {
		t.Fatalf("parseYAML() error: %v", err)
	}
	if len(cfg.IgnorePaths) != 3 {
		t.Fatalf("IgnorePaths len = %d, want 3", len(cfg.IgnorePaths))
	}
	if cfg.IgnorePaths[0] != "vendor/" {
		t.Errorf("IgnorePaths[0] = %q, want %q", cfg.IgnorePaths[0], "vendor/")
	}
	if cfg.IgnorePaths[1] != "*.git*" {
		t.Errorf("IgnorePaths[1] = %q, want %q", cfg.IgnorePaths[1], "*.git*")
	}
	if cfg.IgnorePaths[2] != "node_modules/" {
		t.Errorf("IgnorePaths[2] = %q, want %q", cfg.IgnorePaths[2], "node_modules/")
	}
	if len(cfg.Extensions) != 2 {
		t.Fatalf("Extensions len = %d, want 2", len(cfg.Extensions))
	}
	if cfg.Extensions[0] != ".py" {
		t.Errorf("Extensions[0] = %q, want %q", cfg.Extensions[0], ".py")
	}
	if cfg.Extensions[1] != ".js" {
		t.Errorf("Extensions[1] = %q, want %q", cfg.Extensions[1], ".js")
	}
}

func TestParseYAML_CommentsStripped(t *testing.T) {
	data := []byte(`# This is a comment
min_severity: high # inline comment
output_format: json
# Another comment
enable_ml: false
`)
	cfg := Default()
	if err := parseYAML(data, cfg); err != nil {
		t.Fatalf("parseYAML() error: %v", err)
	}
	if cfg.MinSeverity != "high" {
		t.Errorf("MinSeverity = %q, want %q", cfg.MinSeverity, "high")
	}
	if cfg.OutputFormat != "json" {
		t.Errorf("OutputFormat = %q, want %q", cfg.OutputFormat, "json")
	}
	if cfg.EnableML != false {
		t.Errorf("EnableML = %v, want false", cfg.EnableML)
	}
}

func TestParseYAML_QuotedStrings(t *testing.T) {
	data := []byte(`min_severity: "high"
output_format: 'sarif'
model_path: "/path/to/model.onnx"
`)
	cfg := Default()
	if err := parseYAML(data, cfg); err != nil {
		t.Fatalf("parseYAML() error: %v", err)
	}
	if cfg.MinSeverity != "high" {
		t.Errorf("MinSeverity = %q, want %q", cfg.MinSeverity, "high")
	}
	if cfg.OutputFormat != "sarif" {
		t.Errorf("OutputFormat = %q, want %q", cfg.OutputFormat, "sarif")
	}
	if cfg.ModelPath != "/path/to/model.onnx" {
		t.Errorf("ModelPath = %q, want %q", cfg.ModelPath, "/path/to/model.onnx")
	}
}

func TestParseYAML_EmptyLines(t *testing.T) {
	data := []byte(`min_severity: high

output_format: json

enable_ml: false
`)
	cfg := Default()
	if err := parseYAML(data, cfg); err != nil {
		t.Fatalf("parseYAML() error: %v", err)
	}
	if cfg.MinSeverity != "high" {
		t.Errorf("MinSeverity = %q, want %q", cfg.MinSeverity, "high")
	}
	if cfg.OutputFormat != "json" {
		t.Errorf("OutputFormat = %q, want %q", cfg.OutputFormat, "json")
	}
	if cfg.EnableML != false {
		t.Errorf("EnableML = %v, want false", cfg.EnableML)
	}
}

func TestParseYAML_InvalidMaxFileSize(t *testing.T) {
	data := []byte(`max_file_size: notanumber
`)
	cfg := Default()
	err := parseYAML(data, cfg)
	if err == nil {
		t.Fatal("parseYAML() expected error for invalid max_file_size, got nil")
	}
	if !contains(err.Error(), "invalid max_file_size") {
		t.Errorf("parseYAML() error = %q, want it to contain 'invalid max_file_size'", err.Error())
	}
}

func TestParseYAML_InvalidMLThreshold(t *testing.T) {
	data := []byte(`ml_threshold: notanumber
`)
	cfg := Default()
	err := parseYAML(data, cfg)
	if err == nil {
		t.Fatal("parseYAML() expected error for invalid ml_threshold, got nil")
	}
	if !contains(err.Error(), "invalid ml_threshold") {
		t.Errorf("parseYAML() error = %q, want it to contain 'invalid ml_threshold'", err.Error())
	}
}

func TestParseYAML_InvalidMaxFindingsPerFile(t *testing.T) {
	data := []byte(`max_findings_per_file: notanumber
`)
	cfg := Default()
	err := parseYAML(data, cfg)
	if err == nil {
		t.Fatal("parseYAML() expected error for invalid max_findings_per_file, got nil")
	}
	if !contains(err.Error(), "invalid max_findings_per_file") {
		t.Errorf("parseYAML() error = %q, want it to contain 'invalid max_findings_per_file'", err.Error())
	}
}

func TestParseYAML_LineWithoutColon_Skipped(t *testing.T) {
	data := []byte(`this line has no colon
min_severity: high
`)
	cfg := Default()
	if err := parseYAML(data, cfg); err != nil {
		t.Fatalf("parseYAML() error: %v", err)
	}
	if cfg.MinSeverity != "high" {
		t.Errorf("MinSeverity = %q, want %q", cfg.MinSeverity, "high")
	}
}

func TestParseYAML_EmptyData(t *testing.T) {
	cfg := Default()
	if err := parseYAML([]byte(""), cfg); err != nil {
		t.Fatalf("parseYAML() error: %v", err)
	}
	// Should still be default values
	if cfg.MinSeverity != "low" {
		t.Errorf("MinSeverity = %q, want %q", cfg.MinSeverity, "low")
	}
}

func TestParseYAML_EmptyInlineList(t *testing.T) {
	data := []byte(`ignore_paths: []
extensions: []
`)
	cfg := Default()
	if err := parseYAML(data, cfg); err != nil {
		t.Fatalf("parseYAML() error: %v", err)
	}
	if len(cfg.IgnorePaths) != 0 {
		t.Errorf("IgnorePaths len = %d, want 0", len(cfg.IgnorePaths))
	}
	if len(cfg.Extensions) != 0 {
		t.Errorf("Extensions len = %d, want 0", len(cfg.Extensions))
	}
}

func TestParseYAML_AllConfigKeys(t *testing.T) {
	data := []byte(`ignore_paths: [a/, b/]
extensions: [.py, .js]
max_file_size: 2097152
follow_symlinks: true
min_severity: critical
enable_ml: true
ml_threshold: 0.90
max_findings_per_file: 500
output_format: sarif
color_output: true
model_path: /custom/model.onnx
`)
	cfg := Default()
	if err := parseYAML(data, cfg); err != nil {
		t.Fatalf("parseYAML() error: %v", err)
	}
	if len(cfg.IgnorePaths) != 2 || cfg.IgnorePaths[0] != "a/" || cfg.IgnorePaths[1] != "b/" {
		t.Errorf("IgnorePaths = %v, want [a/ b/]", cfg.IgnorePaths)
	}
	if len(cfg.Extensions) != 2 || cfg.Extensions[0] != ".py" || cfg.Extensions[1] != ".js" {
		t.Errorf("Extensions = %v, want [.py .js]", cfg.Extensions)
	}
	if cfg.MaxFileSize != 2097152 {
		t.Errorf("MaxFileSize = %d, want 2097152", cfg.MaxFileSize)
	}
	if cfg.FollowSymlinks != true {
		t.Errorf("FollowSymlinks = %v, want true", cfg.FollowSymlinks)
	}
	if cfg.MinSeverity != "critical" {
		t.Errorf("MinSeverity = %q, want %q", cfg.MinSeverity, "critical")
	}
	if cfg.EnableML != true {
		t.Errorf("EnableML = %v, want true", cfg.EnableML)
	}
	if cfg.MLThreshold != 0.90 {
		t.Errorf("MLThreshold = %f, want 0.90", cfg.MLThreshold)
	}
	if cfg.MaxFindingsPerFile != 500 {
		t.Errorf("MaxFindingsPerFile = %d, want 500", cfg.MaxFindingsPerFile)
	}
	if cfg.OutputFormat != "sarif" {
		t.Errorf("OutputFormat = %q, want %q", cfg.OutputFormat, "sarif")
	}
	if cfg.ColorOutput != true {
		t.Errorf("ColorOutput = %v, want true", cfg.ColorOutput)
	}
	if cfg.ModelPath != "/custom/model.onnx" {
		t.Errorf("ModelPath = %q, want %q", cfg.ModelPath, "/custom/model.onnx")
	}
}

func TestParseYAML_BlockListAfterNonListKey(t *testing.T) {
	data := []byte(`min_severity: high
ignore_paths:
  - vendor/
  - "*.git*"
`)
	cfg := Default()
	if err := parseYAML(data, cfg); err != nil {
		t.Fatalf("parseYAML() error: %v", err)
	}
	if cfg.MinSeverity != "high" {
		t.Errorf("MinSeverity = %q, want %q", cfg.MinSeverity, "high")
	}
	if len(cfg.IgnorePaths) != 2 {
		t.Fatalf("IgnorePaths len = %d, want 2", len(cfg.IgnorePaths))
	}
	if cfg.IgnorePaths[0] != "vendor/" {
		t.Errorf("IgnorePaths[0] = %q, want %q", cfg.IgnorePaths[0], "vendor/")
	}
}

func TestParseYAML_BlockListItemWithoutCurrentKey(t *testing.T) {
	// Block list item with no preceding key — should be silently ignored
	data := []byte(`- orphan_item
min_severity: high
`)
	cfg := Default()
	if err := parseYAML(data, cfg); err != nil {
		t.Fatalf("parseYAML() error: %v", err)
	}
	if cfg.MinSeverity != "high" {
		t.Errorf("MinSeverity = %q, want %q", cfg.MinSeverity, "high")
	}
}

func TestParseYAML_CommentWithHashInsideQuotes(t *testing.T) {
	data := []byte(`model_path: "/path#with#hash"
min_severity: high
`)
	cfg := Default()
	if err := parseYAML(data, cfg); err != nil {
		t.Fatalf("parseYAML() error: %v", err)
	}
	if cfg.ModelPath != "/path#with#hash" {
		t.Errorf("ModelPath = %q, want %q", cfg.ModelPath, "/path#with#hash")
	}
}

func TestParseYAML_CRLFLineEndings(t *testing.T) {
	data := []byte("min_severity: high\r\noutput_format: json\r\nenable_ml: false\r\n")
	cfg := Default()
	if err := parseYAML(data, cfg); err != nil {
		t.Fatalf("parseYAML() error: %v", err)
	}
	if cfg.MinSeverity != "high" {
		t.Errorf("MinSeverity = %q, want %q", cfg.MinSeverity, "high")
	}
	if cfg.OutputFormat != "json" {
		t.Errorf("OutputFormat = %q, want %q", cfg.OutputFormat, "json")
	}
	if cfg.EnableML != false {
		t.Errorf("EnableML = %v, want false", cfg.EnableML)
	}
}

func TestParseYAML_BooleanTrueVariations(t *testing.T) {
	trueValues := []string{"true", "True", "TRUE", "yes", "Yes", "on", "1"}
	for _, v := range trueValues {
		data := []byte("enable_ml: " + v + "\n")
		cfg := Default()
		if err := parseYAML(data, cfg); err != nil {
			t.Fatalf("parseYAML() error for enable_ml=%s: %v", v, err)
		}
		if cfg.EnableML != true {
			t.Errorf("enable_ml=%s -> EnableML = %v, want true", v, cfg.EnableML)
		}
	}
}

func TestParseYAML_BooleanFalseVariations(t *testing.T) {
	falseValues := []string{"false", "False", "no", "off", "0", "anything"}
	for _, v := range falseValues {
		data := []byte("enable_ml: " + v + "\n")
		cfg := Default()
		cfg.EnableML = true // Start as true to verify it's set to false
		if err := parseYAML(data, cfg); err != nil {
			t.Fatalf("parseYAML() error for enable_ml=%s: %v", v, err)
		}
		if cfg.EnableML != false {
			t.Errorf("enable_ml=%s -> EnableML = %v, want false", v, cfg.EnableML)
		}
	}
}

func TestParseYAML_UnknownKey_Ignored(t *testing.T) {
	data := []byte(`unknown_key: some_value
min_severity: high
another_unknown: 123
`)
	cfg := Default()
	if err := parseYAML(data, cfg); err != nil {
		t.Fatalf("parseYAML() error: %v", err)
	}
	if cfg.MinSeverity != "high" {
		t.Errorf("MinSeverity = %q, want %q", cfg.MinSeverity, "high")
	}
}

// ---------------------------------------------------------------------
// parseInlineList()
// ---------------------------------------------------------------------

func TestParseInlineList(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"[a, b, c]", []string{"a", "b", "c"}},
		{"[a]", []string{"a"}},
		{"[]", nil},
		{`["a", 'b', c]`, []string{"a", "b", "c"}},
		{`[vendor/, "*.git*", node_modules/]`, []string{"vendor/", "*.git*", "node_modules/"}},
		{`[ .py, .js, .go ]`, []string{".py", ".js", ".go"}},
		{`[]`, nil},
	}
	for _, tc := range tests {
		got := parseInlineList(tc.input)
		if len(got) != len(tc.want) {
			t.Errorf("parseInlineList(%q) = %v (len %d), want %v (len %d)", tc.input, got, len(got), tc.want, len(tc.want))
			continue
		}
		for i, v := range got {
			if v != tc.want[i] {
				t.Errorf("parseInlineList(%q)[%d] = %q, want %q", tc.input, i, v, tc.want[i])
			}
		}
	}
}

func TestParseInlineList_WithSpaces(t *testing.T) {
	result := parseInlineList("[  spaced  ,  values  ]")
	if len(result) != 2 {
		t.Fatalf("len = %d, want 2", len(result))
	}
	if result[0] != "spaced" {
		t.Errorf("result[0] = %q, want %q", result[0], "spaced")
	}
	if result[1] != "values" {
		t.Errorf("result[1] = %q, want %q", result[1], "values")
	}
}

func TestParseInlineList_QuotedItems(t *testing.T) {
	result := parseInlineList(`["double quoted", 'single quoted', unquoted]`)
	if len(result) != 3 {
		t.Fatalf("len = %d, want 3", len(result))
	}
	if result[0] != "double quoted" {
		t.Errorf("result[0] = %q, want %q", result[0], "double quoted")
	}
	if result[1] != "single quoted" {
		t.Errorf("result[1] = %q, want %q", result[1], "single quoted")
	}
	if result[2] != "unquoted" {
		t.Errorf("result[2] = %q, want %q", result[2], "unquoted")
	}
}

func TestParseInlineList_EmptyItems(t *testing.T) {
	result := parseInlineList("[a, , b]")
	if len(result) != 2 {
		t.Fatalf("len = %d, want 2 (empty items should be skipped)", len(result))
	}
	if result[0] != "a" {
		t.Errorf("result[0] = %q, want %q", result[0], "a")
	}
	if result[1] != "b" {
		t.Errorf("result[1] = %q, want %q", result[1], "b")
	}
}

// ---------------------------------------------------------------------
// unquote()
// ---------------------------------------------------------------------

func TestUnquote(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`"hello"`, "hello"},
		{`'hello'`, "hello"},
		{`"hello world"`, "hello world"},
		{`'hello world'`, "hello world"},
		{`hello`, "hello"},
		{`"`, `"`},
		{`'`, `'`},
		{`""`, ""},
		{`''`, ""},
		{`"unmatched`, `"unmatched`},
		{`unmatched"`, `unmatched"`},
		{`a"b`, `a"b`},
		{``, ""},
	}
	for _, tc := range tests {
		got := unquote(tc.input)
		if got != tc.want {
			t.Errorf("unquote(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------
// parseBool()
// ---------------------------------------------------------------------

func TestParseBool(t *testing.T) {
	trueCases := []string{"true", "True", "TRUE", "yes", "Yes", "YES", "on", "On", "ON", "1"}
	for _, s := range trueCases {
		if !parseBool(s) {
			t.Errorf("parseBool(%q) = false, want true", s)
		}
	}
	falseCases := []string{"false", "False", "FALSE", "no", "No", "NO", "off", "Off", "OFF", "0", "", "anything", "2", "yesno"}
	for _, s := range falseCases {
		if parseBool(s) {
			t.Errorf("parseBool(%q) = true, want false", s)
		}
	}
}

// ---------------------------------------------------------------------
// parseInt64()
// ---------------------------------------------------------------------

func TestParseInt64(t *testing.T) {
	tests := []struct {
		input string
		want  int64
		err   bool
	}{
		{"0", 0, false},
		{"42", 42, false},
		{"1048576", 1048576, false},
		{"-1", -1, false},
		{"9999999999", 9999999999, false},
		{"abc", 0, true},
		{"", 0, true},
	}
	for _, tc := range tests {
		got, err := parseInt64(tc.input)
		if tc.err {
			if err == nil {
				t.Errorf("parseInt64(%q) expected error, got nil", tc.input)
			}
		} else {
			if err != nil {
				t.Errorf("parseInt64(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("parseInt64(%q) = %d, want %d", tc.input, got, tc.want)
			}
		}
	}
}

// ---------------------------------------------------------------------
// parseInt()
// ---------------------------------------------------------------------

func TestParseInt(t *testing.T) {
	tests := []struct {
		input string
		want  int
		err   bool
	}{
		{"0", 0, false},
		{"42", 42, false},
		{"500", 500, false},
		{"-1", -1, false},
		{"abc", 0, true},
		{"", 0, true},
	}
	for _, tc := range tests {
		got, err := parseInt(tc.input)
		if tc.err {
			if err == nil {
				t.Errorf("parseInt(%q) expected error, got nil", tc.input)
			}
		} else {
			if err != nil {
				t.Errorf("parseInt(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("parseInt(%q) = %d, want %d", tc.input, got, tc.want)
			}
		}
	}
}

// ---------------------------------------------------------------------
// parseFloat64()
// ---------------------------------------------------------------------

func TestParseFloat64(t *testing.T) {
	tests := []struct {
		input string
		want  float64
		err   bool
	}{
		{"0", 0, false},
		{"0.5", 0.5, false},
		{"0.75", 0.75, false},
		{"1.0", 1.0, false},
		{"0.123", 0.123, false},
		{"abc", 0, true},
		{"", 0, true},
	}
	for _, tc := range tests {
		got, err := parseFloat64(tc.input)
		if tc.err {
			if err == nil {
				t.Errorf("parseFloat64(%q) expected error, got nil", tc.input)
			}
		} else {
			if err != nil {
				t.Errorf("parseFloat64(%q) unexpected error: %v", tc.input, err)
			}
			// Use approximate comparison for floats
			if abs(got-tc.want) > 1e-9 {
				t.Errorf("parseFloat64(%q) = %f, want %f", tc.input, got, tc.want)
			}
		}
	}
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || indexOf(s, substr) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func TestLoadFile_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "custom.yml")
	content := `min_severity: high
enable_ml: false
output_format: json
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFile(configPath)
	if err != nil {
		t.Fatalf("LoadFile error: %v", err)
	}
	if cfg.MinSeverity != "high" {
		t.Errorf("MinSeverity = %q, want 'high'", cfg.MinSeverity)
	}
	if cfg.EnableML != false {
		t.Errorf("EnableML = %v, want false", cfg.EnableML)
	}
	if cfg.OutputFormat != "json" {
		t.Errorf("OutputFormat = %q, want 'json'", cfg.OutputFormat)
	}
}

func TestLoadFile_NonexistentFile(t *testing.T) {
	_, err := LoadFile("/nonexistent/path/to/config.yml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadFile_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "bad.yml")
	// Invalid output_format triggers Validate() error.
	content := "output_format: invalid_format\n"
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadFile(configPath)
	if err == nil {
		t.Error("expected error for invalid output_format in config")
	}
}
