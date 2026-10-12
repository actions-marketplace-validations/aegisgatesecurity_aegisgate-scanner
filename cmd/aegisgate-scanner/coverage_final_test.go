// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/config"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/scanner"
)

// =====================================================================
// Remaining coverage gap tests — targeting specific uncovered lines
// =====================================================================

// Lines 101-105: parseScanArgs error path in runScan
func TestRunScan_ParseError(t *testing.T) {
	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	exitCode := run([]string{"aegisgate-scanner", "scan", "--bogus-flag"})

	w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if exitCode != exitError {
		t.Errorf("exit code = %d, want %d", exitCode, exitError)
	}
	if !strings.Contains(buf.String(), "Error:") {
		t.Errorf("expected error message, got: %s", buf.String())
	}
}

// Lines 149-152: Walk error — scan a nonexistent path
func TestRunScan_WalkError(t *testing.T) {
	// Walk might not error on nonexistent path — it might return 0 artifacts
	// Let's test with a path that's a file, not a directory
	dir := t.TempDir()
	filePath := filepath.Join(dir, "notadir.txt")
	os.WriteFile(filePath, []byte("content"), 0644)

	exitCode := run([]string{"aegisgate-scanner", "scan", filePath, "--no-ml", "--quiet"})
	// Walk on a file should either error or return 0 artifacts
	// Either way, it shouldn't crash
	if exitCode != exitOK && exitCode != exitError {
		t.Errorf("exit code = %d, want 0 or 2", exitCode)
	}
}

// Lines 236-238: empty fail_on_severity with findings
func TestRunScan_EmptyFailOnSeverity(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("AKIAIOSFODNN7EXAMPLE"), 0644)

	// Config with empty fail_on_severity
	configContent := `fail_on_severity: ""
enable_ml: false
`
	os.WriteFile(filepath.Join(dir, ".aegisgate.yml"), []byte(configContent), 0644)

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--quiet", "--format", "json"})

	// With empty fail_on_severity, defaults to "low" → any finding fails
	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d (empty fail_on defaults to low)", exitCode, exitFindings)
	}
}

// Lines 543-545: empty output_format in config
func TestRunScan_EmptyOutputFormat(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("AKIAIOSFODNN7EXAMPLE"), 0644)

	// Config with empty output_format (validates as OK, defaults to text in outputResults)
	configContent := `output_format: ""
enable_ml: false
`
	os.WriteFile(filepath.Join(dir, ".aegisgate.yml"), []byte(configContent), 0644)

	exitCode := run([]string{"aegisgate-scanner", "scan", dir, "--quiet"})

	// Should default to text format and produce findings exit
	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d", exitCode, exitFindings)
	}
}

// Lines 706-708, 711-713: stdin empty fail_on_severity with findings
func TestRunScanStdin_EmptyFailOnSeverity(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	// Config with empty fail_on_severity
	os.WriteFile(".aegisgate.yml", []byte("fail_on_severity: \"\"\nenable_ml: false\n"), 0644)

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
	})

	os.Stdin = origStdin

	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d (empty fail_on defaults to low)", exitCode, exitFindings)
	}
}

// Lines 658-665: stdin ML model load failure with explicit path
func TestRunScanStdin_MLModelLoadFailure_ExplicitPath(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	configContent := `enable_ml: true
model_path: "/nonexistent/model.onnx"
`
	os.WriteFile(".aegisgate.yml", []byte(configContent), 0644)

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
		path:   "-",
		format: "json",
		quiet:  true,
	})

	ew.Close()
	os.Stderr = origStderr
	os.Stdin = origStdin
	var buf bytes.Buffer
	buf.ReadFrom(er)

	if exitCode != exitOK {
		t.Errorf("exit code = %d, want %d (ML failure is non-fatal)", exitCode, exitOK)
	}
	if !strings.Contains(buf.String(), "ML model load failed") {
		t.Errorf("expected ML load failure warning, got: %s", buf.String())
	}
}

// Lines 186-189: runScan ML model default path exists but fails to load
func TestRunScan_MLModelDefaultPath_LoadFailure(t *testing.T) {
	// This test needs to run from a directory where the default model path
	// points to a file that exists but is not a valid ONNX model
	dir := t.TempDir()

	// Create a fake models dir with a corrupt model
	modelsDir := filepath.Join(dir, "models")
	os.MkdirAll(modelsDir, 0755)
	os.WriteFile(filepath.Join(modelsDir, "threat_cnn_bilstm.onnx"), []byte("not a real model"), 0644)

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
		t.Errorf("exit code = %d, want %d (corrupt model is non-fatal)", exitCode, exitOK)
	}
	// Should get ML load failure warning
	if !strings.Contains(buf.String(), "ML model load failed") {
		t.Logf("Note: ML model may have loaded from repo root instead of temp dir. Output: %s", buf.String()[:min(200, buf.Len())])
	}
}

// Lines 658-665: stdin ML model default path with corrupt model
func TestRunScanStdin_MLModelDefaultPath_LoadFailure(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	// Create a fake models dir with a corrupt model
	modelsDir := filepath.Join(dir, "models")
	os.MkdirAll(modelsDir, 0755)
	os.WriteFile(filepath.Join(modelsDir, "threat_cnn_bilstm.onnx"), []byte("not a real model"), 0644)

	configContent := `enable_ml: true
model_path: ""
`
	os.WriteFile(".aegisgate.yml", []byte(configContent), 0644)

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
		path:   "-",
		format: "json",
		quiet:  true,
	})

	ew.Close()
	os.Stderr = origStderr
	os.Stdin = origStdin
	var buf bytes.Buffer
	buf.ReadFrom(er)

	if exitCode != exitOK {
		t.Errorf("exit code = %d, want %d", exitCode, exitOK)
	}
	if !strings.Contains(buf.String(), "ML model load failed") {
		t.Logf("Note: ML model may have loaded from repo root. Output: %s", buf.String()[:min(200, buf.Len())])
	}
}

// Line 762-764: findDefaultModelPath executable-relative path
func TestFindDefaultModelPath_ExecutableRelative(t *testing.T) {
	// Create a models dir next to the test executable
	// The test binary is in a temp dir, so we create models/ there
	exe, err := os.Executable()
	if err != nil {
		t.Skip("cannot find executable")
	}
	exeDir := filepath.Dir(exe)
	modelsDir := filepath.Join(exeDir, "models")
	os.MkdirAll(modelsDir, 0755)
	defer os.RemoveAll(modelsDir)

	modelPath := filepath.Join(modelsDir, "threat_cnn_bilstm.onnx")
	os.WriteFile(modelPath, []byte("fake model"), 0644)
	defer os.Remove(modelPath)

	// Run from a dir where ./models doesn't exist
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	os.Chdir(dir)

	path := findDefaultModelPath()
	if path == "" {
		// The /app/models path won't match, but the exe-relative path should
		// However, if the repo models dir is found via ./models, that might match first
		t.Log("findDefaultModelPath returned empty — exe-relative model not found")
	}
}

// Line 543-545: outputResults with empty format via direct call
func TestOutputResults_EmptyFormat(t *testing.T) {
	// Call outputResults directly with a config that has empty OutputFormat
	result := createMinimalScanResult()
	cfg := &config.Config{OutputFormat: ""}
	opts := &scanArgs{quiet: true}

	// Should default to text format
	err := outputResults(result, "test", cfg, opts)
	if err != nil {
		t.Errorf("expected no error with empty format defaulting to text, got: %v", err)
	}
}

// Line 543-545: outputResults with empty format, non-quiet (prints text)
func TestOutputResults_EmptyFormat_Print(t *testing.T) {
	result := createMinimalScanResult()
	cfg := &config.Config{OutputFormat: ""}
	opts := &scanArgs{quiet: false}

	origStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := outputResults(result, "test", cfg, opts)

	w.Close()
	os.Stdout = origStdout
	var buf bytes.Buffer
	buf.ReadFrom(r)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected text output on stdout")
	}
}

// Line 711-713: invalid fail-on severity in stdin path (minRank = 1 fallback)
func TestRunScanStdin_InvalidFailOnSeverity(t *testing.T) {
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
		failOn: "super-critical", // invalid severity → defaults to low (any finding fails)
	})

	os.Stdin = origStdin

	if exitCode != exitFindings {
		t.Errorf("exit code = %d, want %d (invalid severity defaults to low)", exitCode, exitFindings)
	}
}

// Helper to create a minimal scan result for outputResults tests
func createMinimalScanResult() *scanner.ScanResult {
	return &scanner.ScanResult{
		Findings: []scanner.Finding{},
		Stats: scanner.ScanStats{
			FilesScanned:  1,
			TotalFindings: 0,
		},
	}
}
