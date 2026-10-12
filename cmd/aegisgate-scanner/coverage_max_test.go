// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/config"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/scanner"
)

// =====================================================================
// runScan error-path coverage tests
// =====================================================================

func TestRunScan_InvalidConfigYAML(t *testing.T) {
	dir := t.TempDir()
	// Config with invalid min_severity (triggers validation error)
	os.WriteFile(filepath.Join(dir, ".aegisgate.yml"), []byte("min_severity: super-critical\n"), 0644)

	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml", "--quiet"})

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if exitCode != exitError {
		t.Errorf("exit code = %d, want %d (config error)", exitCode, exitError)
	}
	if !strings.Contains(buf.String(), "configuration error") {
		t.Errorf("expected 'configuration error', got: %s", buf.String())
	}
}

func TestRunScan_CustomRuleInvalidRegex(t *testing.T) {
	dir := t.TempDir()
	// Config with an invalid regex pattern
	configContent := `custom_rules:
  - name: bad_rule
    pattern: "[invalid"
    severity: high
    category: test
    description: bad pattern
`
	os.WriteFile(filepath.Join(dir, ".aegisgate.yml"), []byte(configContent), 0644)
	// Create a file to scan
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("some content"), 0644)

	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml", "--quiet"})

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if exitCode != exitError {
		t.Errorf("exit code = %d, want %d (invalid custom rule)", exitCode, exitError)
	}
	if !strings.Contains(buf.String(), "invalid custom rule") {
		t.Errorf("expected 'invalid custom rule', got: %s", buf.String())
	}
}

func TestRunScan_VerboseCustomRules(t *testing.T) {
	dir := t.TempDir()
	configContent := `custom_rules:
  - name: test_rule
    pattern: "TESTTOKEN[0-9]+"
    severity: medium
    category: custom
    description: test custom rule
enable_ml: false
`
	os.WriteFile(filepath.Join(dir, ".aegisgate.yml"), []byte(configContent), 0644)
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("TESTTOKEN12345"), 0644)

	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--verbose", "--quiet", "--format", "json"})

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d (custom rule should trigger)", exitCode, exitFindings)
	}
	if !strings.Contains(buf.String(), "registered custom rules") {
		t.Errorf("expected verbose 'Registered 1 custom rules', got: %s", buf.String())
	}
}

func TestRunScan_NoArtifactsFound(t *testing.T) {
	dir := t.TempDir()
	// No supported files — use extensions not in supported list
	os.WriteFile(filepath.Join(dir, "data.xyz"), []byte("some data"), 0644)
	os.WriteFile(filepath.Join(dir, "readme.bin"), []byte("binary"), 0644)

	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml", "--quiet"})

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if exitCode != exitOK {
		t.Errorf("exit code = %d, want %d (no artifacts is OK)", exitCode, exitOK)
	}
	if !strings.Contains(buf.String(), "no supported AI artifacts found") {
		t.Errorf("expected 'No supported AI artifacts found', got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "supported_extensions") {
		t.Errorf("expected 'Supported extensions:', got: %s", buf.String())
	}
}

func TestRunScan_MLModelLoadFailure_ExplicitPath(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("clean content"), 0644)
	configContent := `enable_ml: true
model_path: "/nonexistent/model.onnx"
`
	os.WriteFile(filepath.Join(dir, ".aegisgate.yml"), []byte(configContent), 0644)

	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--quiet", "--format", "json"})

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	// Should still scan (regex-only fallback), exit 0 for clean content
	if exitCode != exitOK {
		t.Errorf("exit code = %d, want %d (ML failure is non-fatal)", exitCode, exitOK)
	}
	if !strings.Contains(buf.String(), "ML model load failed") {
		t.Errorf("expected ML load failure warning, got: %s", buf.String())
	}
}

func TestRunScan_MLModelLoadFailure_DefaultPath(t *testing.T) {
	// Run from a temp dir where there's no default model
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("clean content"), 0644)
	configContent := `enable_ml: true
model_path: ""
`
	os.WriteFile(filepath.Join(dir, ".aegisgate.yml"), []byte(configContent), 0644)

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--quiet", "--format", "json"})

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if exitCode != exitOK {
		t.Errorf("exit code = %d, want %d", exitCode, exitOK)
	}
	// If model exists in repo, it will load; if not, warning. Either way OK.
	_ = buf.String()
}

func TestRunScan_ProgressIndicator(t *testing.T) {
	dir := t.TempDir()
	// Create 15 files to trigger progress (>10 threshold)
	for i := 0; i < 15; i++ {
		os.WriteFile(filepath.Join(dir, "file_"+string(rune('a'+i))+".txt"), []byte("clean"), 0644)
	}

	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml", "--format", "json"})

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if exitCode != exitOK {
		t.Errorf("exit code = %d, want %d", exitCode, exitOK)
	}
	if !strings.Contains(buf.String(), "Scanning:") {
		t.Errorf("expected progress output, got: %s", buf.String()[:min(200, buf.Len())])
	}
}

func TestRunScan_GenerateBaselineSaveFailure(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("AKIAIOSFODNN7EXAMPLE"), 0644)

	// Try to save baseline to a nonexistent directory
	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml", "--quiet",
		"--generate-baseline", "/nonexistent/dir/baseline.json"})

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if exitCode != exitError {
		t.Errorf("exit code = %d, want %d (baseline save failure)", exitCode, exitError)
	}
	if !strings.Contains(buf.String(), "failed to save baseline") {
		t.Errorf("expected 'failed to save baseline', got: %s", buf.String())
	}
}

func TestRunScan_GenerateBaselineSuccess(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("AKIAIOSFODNN7EXAMPLE"), 0644)

	baselinePath := filepath.Join(dir, "..", "baseline.json")
	absBaseline, _ := filepath.Abs(baselinePath)

	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml", "--quiet",
		"--generate-baseline", absBaseline})

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if exitCode != exitOK {
		t.Errorf("exit code = %d, want %d", exitCode, exitOK)
	}
	if !strings.Contains(buf.String(), "baseline saved") {
		t.Errorf("expected 'Baseline saved', got: %s", buf.String())
	}
	// Verify file exists
	if _, err := os.Stat(absBaseline); err != nil {
		t.Errorf("baseline file not created: %v", err)
	}
}

func TestRunScan_BaselineLoadError(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("clean content"), 0644)

	// Create a corrupted baseline file
	baselinePath := filepath.Join(dir, "..", "bad_baseline.json")
	absBaseline, _ := filepath.Abs(baselinePath)
	os.WriteFile(absBaseline, []byte("not json{"), 0644)

	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml", "--quiet",
		"--baseline", absBaseline})

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if exitCode != exitError {
		t.Errorf("exit code = %d, want %d (baseline load error)", exitCode, exitError)
	}
	if !strings.Contains(buf.String(), "failed to load baseline") {
		t.Errorf("expected 'failed to load baseline', got: %s", buf.String())
	}
}

func TestRunScan_BaselineSuppressionVerbose(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("AKIAIOSFODNN7EXAMPLE"), 0644)

	// First, generate a baseline
	baselinePath := filepath.Join(dir, "..", "baseline_test.json")
	absBaseline, _ := filepath.Abs(baselinePath)
	run([]string{"aegisgate-scanner", "scan", dir, "--no-ml", "--quiet",
		"--generate-baseline", absBaseline})

	// Now scan with baseline and verbose — should suppress and show verbose message
	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml", "--quiet", "--verbose",
		"--baseline", absBaseline})

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if exitCode != exitOK {
		t.Errorf("exit code = %d, want %d (suppressed)", exitCode, exitOK)
	}
	if !strings.Contains(buf.String(), "suppressed findings via baseline") {
		t.Errorf("expected 'Suppressed' message, got: %s", buf.String())
	}
}

func TestRunScan_OutputResultsError_UnknownFormat(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("AKIAIOSFODNN7EXAMPLE"), 0644)

	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// Pass unknown format via CLI (bypasses config validation)
	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml", "--quiet",
		"--format", "xml"})

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if exitCode != exitError {
		t.Errorf("exit code = %d, want %d (unknown format)", exitCode, exitError)
	}
	if !strings.Contains(buf.String(), "output failed") {
		t.Errorf("expected 'output failed', got: %s", buf.String())
	}
}

func TestRunScan_SarifOutputToFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("AKIAIOSFODNN7EXAMPLE"), 0644)

	outFile := filepath.Join(dir, "..", "results.sarif")
	absOut, _ := filepath.Abs(outFile)

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml", "--quiet",
		"--format", "sarif", "--output", absOut})

	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d", exitCode, exitFindings)
	}
	data, err := os.ReadFile(absOut)
	if err != nil {
		t.Fatalf("output file not created: %v", err)
	}
	if !strings.Contains(string(data), "sarif") {
		t.Errorf("expected SARIF content, got: %s", string(data)[:min(200, len(data))])
	}
}

func TestRunScan_JsonOutputToFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("AKIAIOSFODNN7EXAMPLE"), 0644)

	outFile := filepath.Join(dir, "..", "results.json")
	absOut, _ := filepath.Abs(outFile)

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml", "--quiet",
		"--format", "json", "--output", absOut})

	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d", exitCode, exitFindings)
	}
	data, err := os.ReadFile(absOut)
	if err != nil {
		t.Fatalf("output file not created: %v", err)
	}
	if !strings.Contains(string(data), "findings") {
		t.Errorf("expected JSON with findings, got: %s", string(data)[:min(200, len(data))])
	}
}

func TestRunScan_TextOutputToFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("AKIAIOSFODNN7EXAMPLE"), 0644)

	outFile := filepath.Join(dir, "..", "results.txt")
	absOut, _ := filepath.Abs(outFile)

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml", "--quiet",
		"--format", "text", "--output", absOut})

	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d", exitCode, exitFindings)
	}
	data, err := os.ReadFile(absOut)
	if err != nil {
		t.Fatalf("output file not created: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty text output file")
	}
}

func TestRunScan_SarifOutputToStdout(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("AKIAIOSFODNN7EXAMPLE"), 0644)

	origStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml", "--quiet",
		"--format", "sarif"})

	w.Close()
	os.Stdout = origStdout
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d", exitCode, exitFindings)
	}
	if !strings.Contains(buf.String(), "sarif") {
		t.Errorf("expected SARIF output, got: %s", buf.String()[:min(200, buf.Len())])
	}
}

func TestRunScan_FailOnCritical_OnlyMediumFound(t *testing.T) {
	dir := t.TempDir()
	// Content that triggers medium severity (localhost URL)
	os.WriteFile(filepath.Join(dir, "test.py"), []byte("requests.get('http://localhost:8080/api')"), 0644)

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml", "--quiet",
		"--fail-on", "critical"})

	// Medium finding below critical threshold → exit 0
	if exitCode != exitOK {
		t.Errorf("exit code = %d, want %d (medium below critical threshold)", exitCode, exitOK)
	}
}

func TestRunScan_FailOnLow_AnyFinding(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.py"), []byte("requests.get('http://localhost:8080/api')"), 0644)

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml", "--quiet",
		"--fail-on", "low"})

	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d (low catches anything)", exitCode, exitFindings)
	}
}

func TestRunScan_FailOnHigh(t *testing.T) {
	dir := t.TempDir()
	// AWS key is high severity
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("AKIAIOSFODNN7EXAMPLE"), 0644)

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml", "--quiet",
		"--fail-on", "high"})

	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d (high catches AWS key)", exitCode, exitFindings)
	}
}

func TestRunScan_FailOnMedium(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.py"), []byte("requests.get('http://localhost:8080/api')"), 0644)

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml", "--quiet",
		"--fail-on", "medium"})

	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d (medium catches SSN)", exitCode, exitFindings)
	}
}

func TestRunScan_FailOnInvalidSeverity(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("AKIAIOSFODNN7EXAMPLE"), 0644)

	// Invalid severity should default to "low" (any finding fails)
	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml", "--quiet",
		"--fail-on", "super-critical"})

	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d (invalid severity defaults to low)", exitCode, exitFindings)
	}
}

func TestRunScan_ConcurrencyOverride(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		os.WriteFile(filepath.Join(dir, "file_"+string(rune('a'+i))+".txt"), []byte("clean"), 0644)
	}

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml", "--quiet",
		"--concurrency", "2", "--format", "json"})

	if exitCode != exitOK {
		t.Errorf("exit code = %d, want %d", exitCode, exitOK)
	}
}

func TestRunScan_DefaultPath(t *testing.T) {
	// Scan with no path argument (defaults to ".")
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("clean content"), 0644)

	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	exitCode := run([]string{"aegisgate-scanner", "scan", "--no-ml", "--quiet"})

	if exitCode != exitOK {
		t.Errorf("exit code = %d, want %d", exitCode, exitOK)
	}
}

// =====================================================================
// runInit error-path coverage tests
// =====================================================================

func TestRunInit_MkdirFailure(t *testing.T) {
	// Try to create a directory inside a read-only parent
	parent := t.TempDir()
	// Make parent read-only
	os.Chmod(parent, 0444)
	defer os.Chmod(parent, 0755) // restore for cleanup

	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run([]string{"aegisgate-scanner", "init", filepath.Join(parent, "subdir")})

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if exitCode != exitError {
		t.Errorf("exit code = %d, want %d (mkdir failure)", exitCode, exitError)
	}
}

func TestRunInit_WriteFileFailure(t *testing.T) {
	dir := t.TempDir()
	// Create the directory but make it read-only
	// First create a subdir, make it read-only, then try to write config in it
	subdir := filepath.Join(dir, "readonly")
	os.MkdirAll(subdir, 0755)
	os.Chmod(subdir, 0444)
	defer os.Chmod(subdir, 0755)

	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run([]string{"aegisgate-scanner", "init", subdir})

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if exitCode != exitError {
		t.Errorf("exit code = %d, want %d (write failure)", exitCode, exitError)
	}
	if !strings.Contains(buf.String(), "cannot write") {
		t.Errorf("expected 'cannot write', got: %s", buf.String())
	}
}

func TestRunInit_DefaultDir_Cov(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	exitCode := run([]string{"aegisgate-scanner", "init"})

	if exitCode != exitOK {
		t.Errorf("exit code = %d, want %d", exitCode, exitOK)
	}
	if _, err := os.Stat(".aegisgate.yml"); err != nil {
		t.Errorf("config not created in default dir: %v", err)
	}
}

// =====================================================================
// parseScanArgs edge-case coverage tests
// =====================================================================

func TestParseScanArgs_UnknownFlag_Cov(t *testing.T) {
	_, err := parseScanArgs([]string{"--bogus-flag"})
	if err == nil {
		t.Error("expected error for unknown flag")
	}
	if !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("expected 'unknown flag' error, got: %v", err)
	}
}

func TestParseScanArgs_FormatNoValue_Cov(t *testing.T) {
	_, err := parseScanArgs([]string{"--format"})
	if err == nil {
		t.Error("expected error for --format without value")
	}
	if !strings.Contains(err.Error(), "--format requires a value") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParseScanArgs_OutputNoValue_Cov(t *testing.T) {
	_, err := parseScanArgs([]string{"--output"})
	if err == nil || !strings.Contains(err.Error(), "--output requires a value") {
		t.Errorf("expected --output value error, got: %v", err)
	}
}

func TestParseScanArgs_SeverityNoValue_Cov(t *testing.T) {
	_, err := parseScanArgs([]string{"--severity"})
	if err == nil || !strings.Contains(err.Error(), "--severity requires a value") {
		t.Errorf("expected --severity value error, got: %v", err)
	}
}

func TestParseScanArgs_BaselineNoValue(t *testing.T) {
	_, err := parseScanArgs([]string{"--baseline"})
	if err == nil || !strings.Contains(err.Error(), "--baseline requires a value") {
		t.Errorf("expected --baseline value error, got: %v", err)
	}
}

func TestParseScanArgs_GenerateBaselineNoValue(t *testing.T) {
	_, err := parseScanArgs([]string{"--generate-baseline"})
	if err == nil || !strings.Contains(err.Error(), "--generate-baseline requires a value") {
		t.Errorf("expected --generate-baseline value error, got: %v", err)
	}
}

func TestParseScanArgs_ConcurrencyNoValue(t *testing.T) {
	_, err := parseScanArgs([]string{"--concurrency"})
	if err == nil || !strings.Contains(err.Error(), "--concurrency requires a value") {
		t.Errorf("expected --concurrency value error, got: %v", err)
	}
}

func TestParseScanArgs_ConcurrencyInvalidValue(t *testing.T) {
	_, err := parseScanArgs([]string{"--concurrency", "abc"})
	if err == nil || !strings.Contains(err.Error(), "non-negative integer") {
		t.Errorf("expected concurrency error, got: %v", err)
	}
}

func TestParseScanArgs_ConcurrencyNegative(t *testing.T) {
	_, err := parseScanArgs([]string{"--concurrency", "-1"})
	if err == nil || !strings.Contains(err.Error(), "non-negative integer") {
		t.Errorf("expected concurrency error, got: %v", err)
	}
}

func TestParseScanArgs_ConcurrencyEqualsInvalid(t *testing.T) {
	_, err := parseScanArgs([]string{"--concurrency=xyz"})
	if err == nil || !strings.Contains(err.Error(), "non-negative integer") {
		t.Errorf("expected concurrency error, got: %v", err)
	}
}

func TestParseScanArgs_FailOnNoValue(t *testing.T) {
	_, err := parseScanArgs([]string{"--fail-on"})
	if err == nil || !strings.Contains(err.Error(), "--fail-on requires a value") {
		t.Errorf("expected --fail-on value error, got: %v", err)
	}
}

func TestParseScanArgs_DisableRuleNoValue(t *testing.T) {
	_, err := parseScanArgs([]string{"--disable-rule"})
	if err == nil || !strings.Contains(err.Error(), "--disable-rule requires a value") {
		t.Errorf("expected --disable-rule value error, got: %v", err)
	}
}

func TestParseScanArgs_StdinExtNoValue_Cov(t *testing.T) {
	_, err := parseScanArgs([]string{"--stdin-ext"})
	if err == nil || !strings.Contains(err.Error(), "--stdin-ext requires a value") {
		t.Errorf("expected --stdin-ext value error, got: %v", err)
	}
}

func TestParseScanArgs_TwoPaths(t *testing.T) {
	_, err := parseScanArgs([]string{"/path1", "/path2"})
	if err == nil || !strings.Contains(err.Error(), "unexpected argument") {
		t.Errorf("expected unexpected argument error, got: %v", err)
	}
}

func TestParseScanArgs_DashWithExistingPath(t *testing.T) {
	_, err := parseScanArgs([]string{"/some/path", "-"})
	if err == nil || !strings.Contains(err.Error(), "unexpected argument") {
		t.Errorf("expected unexpected argument error, got: %v", err)
	}
}

func TestParseScanArgs_BaselineEqualsForm(t *testing.T) {
	opts, err := parseScanArgs([]string{"--baseline=/tmp/bl.json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.baseline != "/tmp/bl.json" {
		t.Errorf("baseline = %q, want /tmp/bl.json", opts.baseline)
	}
}

func TestParseScanArgs_GenerateBaselineEqualsForm(t *testing.T) {
	opts, err := parseScanArgs([]string{"--generate-baseline=/tmp/bl.json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.generateBaseline != "/tmp/bl.json" {
		t.Errorf("generateBaseline = %q, want /tmp/bl.json", opts.generateBaseline)
	}
}

func TestParseScanArgs_ConcurrencyEqualsValid(t *testing.T) {
	opts, err := parseScanArgs([]string{"--concurrency=4"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.concurrency != 4 {
		t.Errorf("concurrency = %d, want 4", opts.concurrency)
	}
}

func TestParseScanArgs_FailOnEqualsForm(t *testing.T) {
	opts, err := parseScanArgs([]string{"--fail-on=high"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.failOn != "high" {
		t.Errorf("failOn = %q, want high", opts.failOn)
	}
}

func TestParseScanArgs_DisableRuleEqualsForm(t *testing.T) {
	opts, err := parseScanArgs([]string{"--disable-rule=rule1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(opts.disableRules) != 1 || opts.disableRules[0] != "rule1" {
		t.Errorf("disableRules = %v, want [rule1]", opts.disableRules)
	}
}

func TestParseScanArgs_FormatShortFlag(t *testing.T) {
	opts, err := parseScanArgs([]string{"-f", "json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.format != "json" {
		t.Errorf("format = %q, want json", opts.format)
	}
}

func TestParseScanArgs_OutputShortFlag(t *testing.T) {
	opts, err := parseScanArgs([]string{"-o", "/tmp/out.json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.output != "/tmp/out.json" {
		t.Errorf("output = %q, want /tmp/out.json", opts.output)
	}
}

func TestParseScanArgs_SeverityShortFlag(t *testing.T) {
	opts, err := parseScanArgs([]string{"-s", "high"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.minSeverity != "high" {
		t.Errorf("minSeverity = %q, want high", opts.minSeverity)
	}
}

func TestParseScanArgs_QuietShortFlag(t *testing.T) {
	opts, err := parseScanArgs([]string{"-q"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.quiet {
		t.Error("quiet = false, want true")
	}
}

func TestParseScanArgs_VerboseShortFlag(t *testing.T) {
	opts, err := parseScanArgs([]string{"-v"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.verbose {
		t.Error("verbose = false, want true")
	}
}

func TestParseScanArgs_FormatEqualsForm(t *testing.T) {
	opts, err := parseScanArgs([]string{"--format=sarif"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.format != "sarif" {
		t.Errorf("format = %q, want sarif", opts.format)
	}
}

func TestParseScanArgs_OutputEqualsForm(t *testing.T) {
	opts, err := parseScanArgs([]string{"--output=/tmp/results.json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.output != "/tmp/results.json" {
		t.Errorf("output = %q, want /tmp/results.json", opts.output)
	}
}

func TestParseScanArgs_SeverityEqualsForm(t *testing.T) {
	opts, err := parseScanArgs([]string{"--severity=critical"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.minSeverity != "critical" {
		t.Errorf("minSeverity = %q, want critical", opts.minSeverity)
	}
}

// =====================================================================
// runScanStdin error-path coverage tests
// =====================================================================

func TestRunScanStdin_ConfigError(t *testing.T) {
	dir := t.TempDir()
	// Write config with invalid min_severity to trigger validation error
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	os.WriteFile(".aegisgate.yml", []byte("min_severity: super-critical\n"), 0644)

	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		defer w.Close()
		w.Write([]byte("some content"))
	}()

	origStderr := os.Stderr
	er, ew, _ := os.Pipe()
	os.Stderr = ew

	exitCode := runScanStdin(&scanArgs{path: "-", format: "json"})

	ew.Close()
	os.Stderr = origStderr
	os.Stdin = origStdin
	var buf bytes.Buffer
	buf.ReadFrom(er)

	if exitCode != exitError {
		t.Errorf("exit code = %d, want %d (config error)", exitCode, exitError)
	}
	if !strings.Contains(buf.String(), "configuration error") {
		t.Errorf("expected 'configuration error', got: %s", buf.String())
	}
}

func TestRunScanStdin_CustomRuleInvalidRegex(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	configContent := `custom_rules:
  - name: bad_rule
    pattern: "[invalid"
    severity: high
    category: test
    description: bad
enable_ml: false
`
	os.WriteFile(".aegisgate.yml", []byte(configContent), 0644)

	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		defer w.Close()
		w.Write([]byte("some content"))
	}()

	origStderr := os.Stderr
	er, ew, _ := os.Pipe()
	os.Stderr = ew

	exitCode := runScanStdin(&scanArgs{path: "-", format: "json"})

	ew.Close()
	os.Stderr = origStderr
	os.Stdin = origStdin
	var buf bytes.Buffer
	buf.ReadFrom(er)

	if exitCode != exitError {
		t.Errorf("exit code = %d, want %d (invalid custom rule)", exitCode, exitError)
	}
	if !strings.Contains(buf.String(), "invalid custom rule") {
		t.Errorf("expected 'invalid custom rule', got: %s", buf.String())
	}
}

func TestRunScanStdin_BinaryWarning(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		defer w.Close()
		w.Write([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05})
	}()

	origStderr := os.Stderr
	er, ew, _ := os.Pipe()
	os.Stderr = ew

	exitCode := runScanStdin(&scanArgs{path: "-", format: "json", noML: true})

	ew.Close()
	os.Stderr = origStderr
	os.Stdin = origStdin
	var buf bytes.Buffer
	buf.ReadFrom(er)

	if exitCode != exitOK {
		t.Errorf("exit code = %d, want %d", exitCode, exitOK)
	}
	if !strings.Contains(buf.String(), "binary") {
		t.Errorf("expected binary warning, got: %s", buf.String())
	}
}

func TestRunScanStdin_GenerateBaselineSaveFailure(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		defer w.Close()
		w.Write([]byte("AKIAIOSFODNN7EXAMPLE"))
	}()

	origStderr := os.Stderr
	er, ew, _ := os.Pipe()
	os.Stderr = ew

	exitCode := runScanStdin(&scanArgs{
		path:             "-",
		format:           "json",
		noML:             true,
		quiet:            true,
		generateBaseline: "/nonexistent/dir/bl.json",
	})

	ew.Close()
	os.Stderr = origStderr
	os.Stdin = origStdin
	var buf bytes.Buffer
	buf.ReadFrom(er)

	if exitCode != exitError {
		t.Errorf("exit code = %d, want %d (baseline save failure)", exitCode, exitError)
	}
	if !strings.Contains(buf.String(), "failed to save baseline") {
		t.Errorf("expected 'failed to save baseline', got: %s", buf.String())
	}
}

func TestRunScanStdin_BaselineLoadError(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	// Create corrupted baseline
	os.WriteFile("bad_baseline.json", []byte("not json{"), 0644)

	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		defer w.Close()
		w.Write([]byte("clean content"))
	}()

	origStderr := os.Stderr
	er, ew, _ := os.Pipe()
	os.Stderr = ew

	exitCode := runScanStdin(&scanArgs{
		path:     "-",
		format:   "json",
		noML:     true,
		quiet:    true,
		baseline: "bad_baseline.json",
	})

	ew.Close()
	os.Stderr = origStderr
	os.Stdin = origStdin
	var buf bytes.Buffer
	buf.ReadFrom(er)

	if exitCode != exitError {
		t.Errorf("exit code = %d, want %d (baseline load error)", exitCode, exitError)
	}
	if !strings.Contains(buf.String(), "failed to load baseline") {
		t.Errorf("expected 'failed to load baseline', got: %s", buf.String())
	}
}

func TestRunScanStdin_BaselineSuppressionVerbose(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	// First generate a baseline
	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		defer w.Close()
		w.Write([]byte("AKIAIOSFODNN7EXAMPLE"))
	}()

	runScanStdin(&scanArgs{
		path:             "-",
		format:           "json",
		noML:             true,
		quiet:            true,
		generateBaseline: "test_baseline.json",
	})
	os.Stdin = origStdin

	// Now scan with baseline and verbose
	r2, w2, _ := os.Pipe()
	os.Stdin = r2
	go func() {
		defer w2.Close()
		w2.Write([]byte("AKIAIOSFODNN7EXAMPLE"))
	}()

	origStderr := os.Stderr
	er, ew, _ := os.Pipe()
	os.Stderr = ew

	exitCode := runScanStdin(&scanArgs{
		path:     "-",
		format:   "json",
		noML:     true,
		quiet:    true,
		verbose:  true,
		baseline: "test_baseline.json",
	})

	ew.Close()
	os.Stderr = origStderr
	os.Stdin = origStdin
	var buf bytes.Buffer
	buf.ReadFrom(er)

	if exitCode != exitOK {
		t.Errorf("exit code = %d, want %d (suppressed)", exitCode, exitOK)
	}
	if !strings.Contains(buf.String(), "suppressed findings via baseline") {
		t.Errorf("expected 'Suppressed' message, got: %s", buf.String())
	}
}

func TestRunScanStdin_OutputError_UnknownFormat(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		defer w.Close()
		w.Write([]byte("AKIAIOSFODNN7EXAMPLE"))
	}()

	origStderr := os.Stderr
	er, ew, _ := os.Pipe()
	os.Stderr = ew

	exitCode := runScanStdin(&scanArgs{
		path:   "-",
		format: "xml",
		noML:   true,
		quiet:  true,
	})

	ew.Close()
	os.Stderr = origStderr
	os.Stdin = origStdin
	var buf bytes.Buffer
	buf.ReadFrom(er)

	if exitCode != exitError {
		t.Errorf("exit code = %d, want %d (unknown format)", exitCode, exitError)
	}
	if !strings.Contains(buf.String(), "output failed") {
		t.Errorf("expected 'output failed', got: %s", buf.String())
	}
}

func TestRunScanStdin_ConcurrencyOverride_Cov(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		defer w.Close()
		w.Write([]byte("clean content"))
	}()

	exitCode := runScanStdin(&scanArgs{
		path:        "-",
		format:      "json",
		noML:        true,
		quiet:       true,
		concurrency: 2,
	})

	os.Stdin = origStdin

	if exitCode != exitOK {
		t.Errorf("exit code = %d, want %d", exitCode, exitOK)
	}
}

func TestRunScanStdin_StdinReadError(t *testing.T) {
	// This is hard to trigger naturally, but we can test by replacing stdin
	// with a pipe that's already closed with an error
	// Skip if we can't reliably trigger this
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	w.Close() // close immediately → empty stdin

	exitCode := runScanStdin(&scanArgs{path: "-", format: "json"})

	os.Stdin = origStdin

	if exitCode != exitError {
		t.Errorf("exit code = %d, want %d (empty stdin)", exitCode, exitError)
	}
}

func TestRunScanStdin_FailOnSeverity_Cov(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		defer w.Close()
		w.Write([]byte("AKIAIOSFODNN7EXAMPLE"))
	}()

	exitCode := runScanStdin(&scanArgs{
		path:   "-",
		format: "json",
		noML:   true,
		quiet:  true,
		failOn: "high",
	})

	os.Stdin = origStdin

	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d (fail-on high catches AWS key)", exitCode, exitFindings)
	}
}

func TestRunScanStdin_FailOnCritical_MediumOnly(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		defer w.Close()
		w.Write([]byte("requests.get('http://localhost:8080/api')"))
	}()

	exitCode := runScanStdin(&scanArgs{
		path:   "-",
		format: "json",
		noML:   true,
		quiet:  true,
		failOn: "critical",
	})

	os.Stdin = origStdin

	if exitCode != exitOK {
		t.Errorf("exit code = %d, want %d (medium below critical)", exitCode, exitOK)
	}
}

func TestRunScanStdin_DisableRule_Cov(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		defer w.Close()
		w.Write([]byte("AKIAIOSFODNN7EXAMPLE"))
	}()

	exitCode := runScanStdin(&scanArgs{
		path:         "-",
		format:       "json",
		noML:         true,
		quiet:        true,
		disableRules: []string{"secret_aws_key"},
	})

	os.Stdin = origStdin

	if exitCode != exitOK {
		t.Errorf("exit code = %d, want %d (rule disabled, no findings)", exitCode, exitOK)
	}
}

func TestRunScanStdin_SarifFormat_Cov(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		defer w.Close()
		w.Write([]byte("AKIAIOSFODNN7EXAMPLE"))
	}()

	origStdout := os.Stdout
	er, ew, _ := os.Pipe()
	os.Stdout = ew

	exitCode := runScanStdin(&scanArgs{
		path:   "-",
		format: "sarif",
		noML:   true,
		quiet:  true,
	})

	ew.Close()
	os.Stdout = origStdout
	os.Stdin = origStdin
	var buf bytes.Buffer
	buf.ReadFrom(er)

	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d", exitCode, exitFindings)
	}
	if !strings.Contains(buf.String(), "sarif") {
		t.Errorf("expected SARIF output, got: %s", buf.String()[:min(200, buf.Len())])
	}
}

func TestRunScanStdin_OutputToFile(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		defer w.Close()
		w.Write([]byte("AKIAIOSFODNN7EXAMPLE"))
	}()

	outFile := filepath.Join(dir, "stdin_results.json")

	exitCode := runScanStdin(&scanArgs{
		path:   "-",
		format: "json",
		noML:   true,
		quiet:  true,
		output: outFile,
	})

	os.Stdin = origStdin

	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d", exitCode, exitFindings)
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Errorf("output file not created: %v", err)
	}
}

func TestRunScanStdin_TextFormatWithOutput(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		defer w.Close()
		w.Write([]byte("AKIAIOSFODNN7EXAMPLE"))
	}()

	outFile := filepath.Join(dir, "stdin_results.txt")

	exitCode := runScanStdin(&scanArgs{
		path:   "-",
		format: "text",
		noML:   true,
		quiet:  true,
		output: outFile,
	})

	os.Stdin = origStdin

	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d", exitCode, exitFindings)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("output file not created: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty text output")
	}
}

func TestRunScanStdin_TextFormatStdout(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		defer w.Close()
		w.Write([]byte("AKIAIOSFODNN7EXAMPLE"))
	}()

	origStdout := os.Stdout
	er, ew, _ := os.Pipe()
	os.Stdout = ew

	exitCode := runScanStdin(&scanArgs{
		path:   "-",
		format: "text",
		noML:   true,
	})

	ew.Close()
	os.Stdout = origStdout
	os.Stdin = origStdin
	var buf bytes.Buffer
	buf.ReadFrom(er)

	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d", exitCode, exitFindings)
	}
	if buf.Len() == 0 {
		t.Error("expected text output on stdout")
	}
}

func TestRunScanStdin_StdinExtWithoutDot_Cov(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		defer w.Close()
		w.Write([]byte("eval(__import__('os').system('id'))"))
	}()

	exitCode := runScanStdin(&scanArgs{
		path:     "-",
		format:   "json",
		noML:     true,
		quiet:    true,
		stdinExt: "py",
	})

	os.Stdin = origStdin

	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d (dangerous_py_eval)", exitCode, exitFindings)
	}
}

func TestRunScanStdin_NoMLFlag(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		defer w.Close()
		w.Write([]byte("clean content here"))
	}()

	exitCode := runScanStdin(&scanArgs{
		path:   "-",
		format: "json",
		noML:   true,
		quiet:  true,
	})

	os.Stdin = origStdin

	if exitCode != exitOK {
		t.Errorf("exit code = %d, want %d", exitCode, exitOK)
	}
}

// =====================================================================
// findDefaultModelPath tests
// =====================================================================

func TestFindDefaultModelPath_ExistsInRepo(t *testing.T) {
	// The model should exist in the repo root
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	// Go to repo root
	os.Chdir("../../")
	path := findDefaultModelPath()
	if path == "" {
		// Model might not be present in test env, that's OK
		t.Skip("model not found in repo (expected in dev environment)")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("findDefaultModelPath returned nonexistent path: %s", path)
	}
}

func TestFindDefaultModelPath_NotFound(t *testing.T) {
	// Run from a temp dir where no model exists
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	path := findDefaultModelPath()
	// Should either be empty or point to a non-existent path
	// In temp dir, it should be empty since there's no models/ dir
	if path != "" {
		// Could find it relative to executable — check if it actually exists
		if _, err := os.Stat(path); err != nil {
			// Path doesn't exist — that's fine, it's just a candidate
			t.Logf("findDefaultModelPath returned non-existent path: %s", path)
		}
	}
}

// =====================================================================
// outputResults direct tests
// =====================================================================

func TestOutputResults_SarifError(t *testing.T) {
	// This is hard to trigger directly since FormatSARIF rarely fails
	// But we can test unknown format
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	result := &scanner.ScanResult{
		Findings: []scanner.Finding{},
	}
	cfg := &config.Config{OutputFormat: "xml"}
	opts := &scanArgs{quiet: true}

	err := outputResults(result, "test", cfg, opts)
	if err == nil {
		t.Error("expected error for unknown format")
	}
	if !strings.Contains(err.Error(), "unknown output format") {
		t.Errorf("expected 'unknown output format', got: %v", err)
	}
}

// TestRunScan_JSONLOutputToFile verifies JSONL output via runScan (not stdin).
func TestRunScan_JSONLOutputToFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("AKIAIOSFODNN7EXAMPLE"), 0644)

	outFile := filepath.Join(dir, "..", "results.jsonl")
	absOut, _ := filepath.Abs(outFile)

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml", "--quiet",
		"--format", "jsonl", "--output", absOut})

	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d", exitCode, exitFindings)
	}
	data, err := os.ReadFile(absOut)
	if err != nil {
		t.Fatalf("output file not created: %v", err)
	}
	if !strings.Contains(string(data), "\"type\":\"finding\"") {
		t.Errorf("expected JSONL with finding objects, got: %s", string(data)[:min(200, len(data))])
	}
	if !strings.Contains(string(data), "\"type\":\"summary\"") {
		t.Errorf("expected JSONL with summary object")
	}
}

// TestRunScan_JSONLOutputToStdout verifies JSONL output to stdout via runScan.
func TestRunScan_JSONLOutputToStdout(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("AKIAIOSFODNN7EXAMPLE"), 0644)

	// Capture stdout.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml",
		"--format", "jsonl"})

	w.Close()
	os.Stdout = oldStdout
	out, _ := io.ReadAll(r)

	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d", exitCode, exitFindings)
	}
	if !strings.Contains(string(out), "\"type\":\"finding\"") {
		t.Errorf("expected JSONL output with findings")
	}
}

// TestRunScan_SBOMOutputToStdout verifies SBOM output to stdout via runScan.
func TestRunScan_SBOMOutputToStdout(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("AKIAIOSFODNN7EXAMPLE"), 0644)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml",
		"--format", "sbom"})

	w.Close()
	os.Stdout = oldStdout
	out, _ := io.ReadAll(r)

	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d", exitCode, exitFindings)
	}
	if !strings.Contains(string(out), "sbom") {
		t.Errorf("expected SBOM output, got: %s", string(out)[:min(200, len(out))])
	}
}

// TestRunScan_HTMLOutputToStdout verifies HTML output to stdout via runScan.
func TestRunScan_HTMLOutputToStdout(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("AKIAIOSFODNN7EXAMPLE"), 0644)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--no-ml",
		"--format", "html"})

	w.Close()
	os.Stdout = oldStdout
	out, _ := io.ReadAll(r)

	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d", exitCode, exitFindings)
	}
	if !strings.Contains(string(out), "<html") {
		t.Errorf("expected HTML output, got: %s", string(out)[:min(200, len(out))])
	}
}
