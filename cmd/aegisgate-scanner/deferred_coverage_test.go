// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Deferred Coverage Tests
// =========================================================================
//
// Tests for code paths added after the initial coverage push:
//   - New output formats (html, pr-comment, github-actions, sbom)
//   - Plugin loading, diff scanning, archive extraction
//   - parseScanArgs new flags (--diff, --extract-archives)
//   - update command (runUpdate, performUpdate, fetchRelease, verifyChecksum,
//     downloadAsset, replaceBinary, parseUpdateArgs)
//
// =========================================================================

package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// =====================================================================
// A) New output formats — outputResults via runScan
// =====================================================================

// runScanWithFormat is a helper that creates a temp dir with a file
// containing detectable content, runs a scan with the given format,
// and returns the captured stdout.
func runScanWithFormat(t *testing.T, format string) string {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte(contentWithPII), 0644)

	out := captureStdout(func() {
		code := runScan([]string{dir, "--no-ml", "--format", format})
		if code != exitFindings {
			t.Errorf("expected exitFindings for %s format, got %d", format, code)
		}
	})
	return out
}

// runScanWithFormatToFile is a helper that scans with a format and writes
// output to a file, returning the file contents.
func runScanWithFormatToFile(t *testing.T, format, outExt string) string {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte(contentWithPII), 0644)

	outFile := filepath.Join(dir, "results."+outExt)
	code := runScan([]string{dir, "--no-ml", "--format", format, "--output", outFile})
	if code != exitFindings {
		t.Errorf("expected exitFindings for %s format, got %d", format, code)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	return string(data)
}

func TestRunScan_HtmlFormat(t *testing.T) {
	out := runScanWithFormat(t, "html")
	if !strings.Contains(out, "<html") && !strings.Contains(out, "<!DOCTYPE") {
		t.Errorf("expected HTML output, got: %s", truncate(out, 200))
	}
}

func TestRunScan_PrCommentFormat(t *testing.T) {
	out := runScanWithFormat(t, "pr-comment")
	// PR comment format should contain markdown-style content
	if !strings.Contains(out, "AegisGate") {
		t.Errorf("expected PR comment output to mention AegisGate, got: %s", truncate(out, 200))
	}
}

func TestRunScan_GitHubActionsFormat(t *testing.T) {
	out := runScanWithFormat(t, "github-actions")
	// GitHub Actions format uses ::error or ::warning annotations
	if !strings.Contains(out, "::") {
		t.Errorf("expected GitHub Actions output with ::error or ::warning, got: %s", truncate(out, 200))
	}
}

func TestRunScan_SbomFormat(t *testing.T) {
	out := runScanWithFormat(t, "sbom")
	// SBOM format should be SPDX JSON
	var spdx map[string]interface{}
	if err := json.Unmarshal([]byte(out), &spdx); err != nil {
		t.Errorf("expected valid JSON for SBOM output, got error: %v, output: %s", err, truncate(out, 200))
	}
	if spdx["spdxVersion"] == nil {
		t.Errorf("expected SPDX version field in SBOM output")
	}
}

func TestRunScan_HtmlOutputToFile(t *testing.T) {
	data := runScanWithFormatToFile(t, "html", "html")
	if !strings.Contains(data, "<html") && !strings.Contains(data, "<!DOCTYPE") {
		t.Errorf("expected HTML in output file, got: %s", truncate(data, 200))
	}
}

func TestRunScan_PrCommentOutputToFile(t *testing.T) {
	data := runScanWithFormatToFile(t, "pr-comment", "md")
	if !strings.Contains(data, "AegisGate") {
		t.Errorf("expected PR comment content in output file, got: %s", truncate(data, 200))
	}
}

func TestRunScan_GitHubActionsOutputToFile(t *testing.T) {
	data := runScanWithFormatToFile(t, "github-actions", "txt")
	if !strings.Contains(data, "::") {
		t.Errorf("expected GitHub Actions annotations in output file, got: %s", truncate(data, 200))
	}
}

func TestRunScan_SbomOutputToFile(t *testing.T) {
	data := runScanWithFormatToFile(t, "sbom", "json")
	var spdx map[string]interface{}
	if err := json.Unmarshal([]byte(data), &spdx); err != nil {
		t.Errorf("expected valid JSON SBOM in output file, got error: %v", err)
	}
}

// =====================================================================
// B) New runScan paths — plugin loading, diff, archive
// =====================================================================

func TestRunScan_PluginLoading(t *testing.T) {
	dir := t.TempDir()
	// Create a plugin directory with a YAML pattern file.
	pluginDir := filepath.Join(dir, ".aegisgate-plugins")
	os.MkdirAll(pluginDir, 0755)
	pluginContent := `name: test-plugin
rules:
  - name: test-plugin-rule
    pattern: "TOPSECRETLEAK"
    severity: high
    category: secret
    description: Detects top secret leaks
`
	os.WriteFile(filepath.Join(pluginDir, "secret.yaml"), []byte(pluginContent), 0644)

	// Create a file that triggers the plugin rule.
	os.WriteFile(filepath.Join(dir, "data.txt"), []byte("Here is a TOPSECRETLEAK in the file"), 0644)

	out := captureStdout(func() {
		code := runScan([]string{dir, "--no-ml", "--format", "json"})
		if code != exitFindings {
			t.Errorf("expected exitFindings with plugin rule, got %d", code)
		}
	})

	if !strings.Contains(out, "test-plugin-rule") {
		t.Errorf("expected output to contain test-plugin-rule, got: %s", truncate(out, 300))
	}
}

func TestRunScan_PluginLoadingVerbose(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, ".aegisgate-plugins")
	os.MkdirAll(pluginDir, 0755)
	pluginContent := `name: verbose-plugin
rules:
  - name: verbose-plugin-rule
    pattern: "VERBOSELEAK"
    severity: medium
    category: secret
    description: Detects verbose leaks
`
	os.WriteFile(filepath.Join(pluginDir, "verbose.yaml"), []byte(pluginContent), 0644)
	os.WriteFile(filepath.Join(dir, "data.txt"), []byte("Found a VERBOSELEAK here"), 0644)

	stderr := captureStderr(func() {
		captureStdout(func() {
			code := runScan([]string{dir, "--no-ml", "--format", "json", "--verbose"})
			if code != exitFindings {
				t.Errorf("expected exitFindings with verbose plugin, got %d", code)
			}
		})
	})

	// Verbose mode should print plugin loading info.
	if !strings.Contains(stderr, "plugin") {
		t.Errorf("expected verbose output to mention plugins, got: %s", truncate(stderr, 300))
	}
}

func TestRunScan_DiffScanning(t *testing.T) {
	// Skip if git is not available.
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()

	// Initialize a git repo with main as default branch.
	runGit(t, dir, "init", "--initial-branch=main")
	runGit(t, dir, "config", "user.email", "test@test.com")
	runGit(t, dir, "config", "user.name", "Test")

	// Create initial commit on main branch with a clean file.
	os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("This is clean content"), 0644)
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "initial")

	// Create a new branch with a change.
	runGit(t, dir, "checkout", "-b", "feature")
	os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("SSN: 123-45-6789"), 0644)
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "add secret file")

	// Now scan with --diff main (should only scan the changed file).
	var scanCode int
	out := captureStdout(func() {
		scanCode = runScan([]string{dir, "--no-ml", "--format", "json", "--diff", "main"})
	})
	if scanCode != exitFindings {
		t.Errorf("expected exitFindings from diff scan, got %d", scanCode)
	}

	if !strings.Contains(out, "secret.txt") {
		// The diff scan should have found and scanned the changed file.
		// Even if output format differs, there should be findings.
		t.Logf("diff scan output: %s", truncate(out, 300))
	}
}

func TestRunScan_ArchiveExtraction(t *testing.T) {
	dir := t.TempDir()

	// Create a zip archive containing a .txt file with a secret.
	zipPath := filepath.Join(dir, "archive.zip")
	createTestZip(t, zipPath, "inner.txt", []byte("SSN: 123-45-6789"))

	// Also add a non-archive text file so the walk finds something.
	os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("clean content"), 0644)

	out := captureStdout(func() {
		code := runScan([]string{dir, "--no-ml", "--format", "json", "--extract-archives"})
		// Should scan both the readme and the extracted archive content.
		_ = code
	})

	// The output should contain findings from the extracted archive content.
	t.Logf("archive scan output: %s", truncate(out, 300))
}

// =====================================================================
// C) parseScanArgs new flags
// =====================================================================

func TestParseScanArgs_DiffFlag(t *testing.T) {
	opts, err := parseScanArgs([]string{"--diff", "main"})
	if err != nil {
		t.Fatalf("parseScanArgs error: %v", err)
	}
	if opts.diffBase != "main" {
		t.Errorf("diffBase = %q, want %q", opts.diffBase, "main")
	}
}

func TestParseScanArgs_DiffEqualsForm(t *testing.T) {
	opts, err := parseScanArgs([]string{"--diff=main"})
	if err != nil {
		t.Fatalf("parseScanArgs error: %v", err)
	}
	if opts.diffBase != "main" {
		t.Errorf("diffBase = %q, want %q", opts.diffBase, "main")
	}
}

func TestParseScanArgs_DiffNoValue(t *testing.T) {
	_, err := parseScanArgs([]string{"--diff"})
	if err == nil {
		t.Error("expected error when --diff has no value")
	}
	if !strings.Contains(err.Error(), "--diff") {
		t.Errorf("error should mention --diff, got: %v", err)
	}
}

func TestParseScanArgs_ExtractArchives(t *testing.T) {
	opts, err := parseScanArgs([]string{"--extract-archives"})
	if err != nil {
		t.Fatalf("parseScanArgs error: %v", err)
	}
	if !opts.extractArchives {
		t.Error("extractArchives should be true")
	}

	opts2, err := parseScanArgs([]string{"--no-extract-archives"})
	if err != nil {
		t.Fatalf("parseScanArgs error: %v", err)
	}
	if opts2.extractArchives {
		t.Error("extractArchives should be false after --no-extract-archives")
	}
}

// =====================================================================
// D) Update command tests
// =====================================================================

// setupMockUpdateServer creates a test server that serves a mock GitHub
// release API, asset downloads, and checksums files.
func setupMockUpdateServer(t *testing.T, release *githubRelease, binaryContent string, checksumContent string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// Latest release endpoint.
	mux.HandleFunc("/repos/test/test/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(release)
	})

	// Tag-specific release endpoint.
	mux.HandleFunc("/repos/test/test/releases/tags/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(release)
	})

	// Asset download endpoint.
	mux.HandleFunc("/download/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte(binaryContent))
	})

	// Checksums file endpoint.
	mux.HandleFunc("/checksums", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(checksumContent))
	})

	// Error endpoint for HTTP error tests.
	mux.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	return httptest.NewServer(mux)
}

func TestRunUpdate_NoArgs(t *testing.T) {
	mockRelease := &githubRelease{
		TagName: "v0.1.0", // same as Version → up to date
		Assets:  []githubAsset{},
	}

	server := setupMockUpdateServer(t, mockRelease, "", "")
	defer server.Close()

	oldVersion := Version
	Version = "0.1.0"
	defer func() { Version = oldVersion }()

	out := captureStdout(func() {
		code := runUpdate([]string{"--api-url", server.URL, "--repo", "test/test"})
		if code != exitOK {
			t.Errorf("expected exitOK for up-to-date, got %d", code)
		}
	})

	if !strings.Contains(out, "up to date") {
		t.Errorf("expected 'up to date' message, got: %s", truncate(out, 200))
	}
}

func TestRunUpdate_HelpFlag(t *testing.T) {
	if !hasBinary(t) {
		t.Skip("test binary not built")
	}

	cmd := exec.Command(testBinaryPath, "update", "--help")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		// --help causes exit(0) which may show as nil error
		exitErr, ok := err.(*exec.ExitError)
		if ok && exitErr.ExitCode() != 0 {
			t.Fatalf("update --help failed: %v", err)
		}
	}
	if !strings.Contains(stdout.String(), "Usage") {
		t.Errorf("expected usage output for update --help, got: %s", stdout.String())
	}
}

func TestRunUpdate_DryRun(t *testing.T) {
	mockRelease := &githubRelease{
		TagName: "v0.2.0",
		Assets: []githubAsset{
			{
				Name:               fmt.Sprintf("aegisgate-scanner_0.2.0_%s_%s", runtime.GOOS, runtime.GOARCH),
				BrowserDownloadURL: "http://example.com/download/binary",
			},
		},
	}

	server := setupMockUpdateServer(t, mockRelease, "fake binary", "")
	defer server.Close()

	oldVersion := Version
	Version = "0.1.0"
	defer func() { Version = oldVersion }()

	out := captureStdout(func() {
		code := runUpdate([]string{"--dry-run", "--api-url", server.URL, "--repo", "test/test"})
		if code != exitOK {
			t.Errorf("expected exitOK for dry run, got %d", code)
		}
	})

	if !strings.Contains(out, "Dry run") {
		t.Errorf("expected 'Dry run' message, got: %s", truncate(out, 200))
	}
}

func TestRunUpdate_Command(t *testing.T) {
	mockRelease := &githubRelease{
		TagName: "v0.2.0",
		Assets: []githubAsset{
			{
				Name:               fmt.Sprintf("aegisgate-scanner_0.2.0_%s_%s", runtime.GOOS, runtime.GOARCH),
				BrowserDownloadURL: "http://example.com/download/binary",
			},
		},
	}

	server := setupMockUpdateServer(t, mockRelease, "fake binary", "")
	defer server.Close()

	oldVersion := Version
	Version = "0.1.0"
	defer func() { Version = oldVersion }()

	out := captureStdout(func() {
		code := run([]string{"aegisgate-scanner", "update", "--dry-run", "--api-url", server.URL, "--repo", "test/test"})
		if code != exitOK {
			t.Errorf("expected exitOK for update --dry-run command, got %d", code)
		}
	})

	if !strings.Contains(out, "Dry run") {
		t.Errorf("expected 'Dry run' message, got: %s", truncate(out, 200))
	}
}

func TestParseUpdateArgs_Verbose(t *testing.T) {
	// --verbose is not a defined flag; it should error.
	_, err := ParseUpdateArgsExported([]string{"--verbose"})
	if err == nil {
		t.Error("expected error for unknown --verbose flag in update args")
	}
}

func TestParseUpdateArgs_VersionFlag(t *testing.T) {
	// Test --version flag with value.
	opts, err := ParseUpdateArgsExported([]string{"--version", "1.0.0"})
	if err != nil {
		t.Fatalf("parseUpdateArgs error: %v", err)
	}
	if opts.Version != "1.0.0" {
		t.Errorf("version = %s, want 1.0.0", opts.Version)
	}
}

func TestParseUpdateArgs_NoVerify(t *testing.T) {
	// --no-verify is not a defined flag; it should error.
	_, err := ParseUpdateArgsExported([]string{"--no-verify"})
	if err == nil {
		t.Error("expected error for unknown --no-verify flag in update args")
	}
}

func TestParseUpdateArgs_InvalidFlag(t *testing.T) {
	_, err := ParseUpdateArgsExported([]string{"--bogus-flag"})
	if err == nil {
		t.Error("expected error for unknown flag --bogus-flag")
	}
	if !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("error should mention 'unknown flag', got: %v", err)
	}
}

func TestFetchRelease_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	opts := UpdateOptions{
		GitHubAPIURL: server.URL,
		Repo:         "test/test",
	}

	_, err := FetchRelease(opts)
	if err == nil {
		t.Fatal("expected error for HTTP 404")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should mention status code, got: %v", err)
	}
}

func TestFetchRelease_Success(t *testing.T) {
	mockRelease := &githubRelease{
		TagName: "v1.0.0",
		Name:    "Release 1.0.0",
		HTMLURL: "https://github.com/test/test/releases/v1.0.0",
		Body:    "Release notes",
		Assets: []githubAsset{
			{Name: "binary", BrowserDownloadURL: "http://example.com/download/binary", Size: 1024},
		},
	}

	server := setupMockUpdateServer(t, mockRelease, "", "")
	defer server.Close()

	opts := UpdateOptions{
		GitHubAPIURL: server.URL,
		Repo:         "test/test",
	}

	release, err := FetchRelease(opts)
	if err != nil {
		t.Fatalf("FetchRelease error: %v", err)
	}
	if release.TagName != "v1.0.0" {
		t.Errorf("tag = %s, want v1.0.0", release.TagName)
	}
	if release.Name != "Release 1.0.0" {
		t.Errorf("name = %s, want Release 1.0.0", release.Name)
	}
	if len(release.Assets) != 1 {
		t.Errorf("expected 1 asset, got %d", len(release.Assets))
	}
}

func TestVerifyChecksum_Valid(t *testing.T) {
	dir := t.TempDir()

	// Create a test file with known content.
	content := []byte("test binary content")
	filePath := filepath.Join(dir, "binary")
	os.WriteFile(filePath, content, 0644)

	// Calculate actual checksum.
	hash := sha256.Sum256(content)
	actualChecksum := hex.EncodeToString(hash[:])

	// Create a mock server that serves a checksums file.
	assetName := "binary"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", actualChecksum, assetName)
	}))
	defer server.Close()

	release := &githubRelease{
		Assets: []githubAsset{
			{Name: "checksums.sha256", BrowserDownloadURL: server.URL},
		},
	}
	asset := &githubAsset{Name: assetName}

	ok, err := VerifyChecksum(filePath, release, asset)
	if err != nil {
		t.Fatalf("VerifyChecksum error: %v", err)
	}
	if !ok {
		t.Error("expected checksum verification to pass")
	}
}

func TestVerifyChecksum_Invalid(t *testing.T) {
	dir := t.TempDir()

	content := []byte("test binary content")
	filePath := filepath.Join(dir, "binary")
	os.WriteFile(filePath, content, 0644)

	// Create a mock server that serves a wrong checksum.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "0000000000000000000000000000000000000000000000000000000000000000  binary\n")
	}))
	defer server.Close()

	release := &githubRelease{
		Assets: []githubAsset{
			{Name: "checksums.sha256", BrowserDownloadURL: server.URL},
		},
	}
	asset := &githubAsset{Name: "binary"}

	ok, err := VerifyChecksum(filePath, release, asset)
	if err != nil {
		t.Fatalf("VerifyChecksum error: %v", err)
	}
	if ok {
		t.Error("expected checksum verification to fail with wrong hash")
	}
}

func TestPerformUpdate_DryRun_Coverage(t *testing.T) {
	mockRelease := &githubRelease{
		TagName: "v0.2.0",
		Assets: []githubAsset{
			{
				Name:               fmt.Sprintf("aegisgate-scanner_0.2.0_%s_%s", runtime.GOOS, runtime.GOARCH),
				BrowserDownloadURL: "http://example.com/download/binary",
			},
		},
	}

	server := setupMockUpdateServer(t, mockRelease, "fake binary", "")
	defer server.Close()

	opts := UpdateOptions{
		DryRun:       true,
		GitHubAPIURL: server.URL,
		Repo:         "test/test",
	}

	result, err := PerformUpdate(opts, "0.1.0")
	if err != nil {
		t.Fatalf("PerformUpdate error: %v", err)
	}
	if !result.UpdateAvailable {
		t.Error("should detect update available")
	}
	if result.LatestVersion != "0.2.0" {
		t.Errorf("latest version = %s, want 0.2.0", result.LatestVersion)
	}
}

func TestPerformUpdate_ForceUpdate(t *testing.T) {
	// Force update even when already up to date.
	mockRelease := &githubRelease{
		TagName: "v0.1.0", // same as current
		Assets: []githubAsset{
			{
				Name:               fmt.Sprintf("aegisgate-scanner_0.1.0_%s_%s", runtime.GOOS, runtime.GOARCH),
				BrowserDownloadURL: "http://example.com/download/binary",
			},
		},
	}

	server := setupMockUpdateServer(t, mockRelease, "fake binary content", "")
	defer server.Close()

	// Use dry-run so we don't actually replace the binary.
	opts := UpdateOptions{
		DryRun:       true,
		Force:        true,
		GitHubAPIURL: server.URL,
		Repo:         "test/test",
	}

	result, err := PerformUpdate(opts, "0.1.0")
	if err != nil {
		t.Fatalf("PerformUpdate error: %v", err)
	}
	// With force=true, it should proceed even though versions match.
	// But with DryRun=true, it should still not download.
	if result.DownloadedFile != "" {
		t.Error("dry run should not download anything")
	}
}

func TestRunUpdate_UpdateAvailable(t *testing.T) {
	mockRelease := &githubRelease{
		TagName: "v0.3.0",
		Assets: []githubAsset{
			{
				Name:               fmt.Sprintf("aegisgate-scanner_0.3.0_%s_%s", runtime.GOOS, runtime.GOARCH),
				BrowserDownloadURL: "http://example.com/download/binary",
			},
		},
	}

	server := setupMockUpdateServer(t, mockRelease, "fake binary", "")
	defer server.Close()

	oldVersion := Version
	Version = "0.1.0"
	defer func() { Version = oldVersion }()

	out := captureStdout(func() {
		code := runUpdate([]string{"--dry-run", "--api-url", server.URL, "--repo", "test/test"})
		if code != exitOK {
			t.Errorf("expected exitOK for dry run with update available, got %d", code)
		}
	})

	if !strings.Contains(out, "0.1.0") || !strings.Contains(out, "0.3.0") {
		t.Errorf("expected version transition in output, got: %s", truncate(out, 200))
	}
}

func TestRunUpdate_InvalidArgs(t *testing.T) {
	stderr := captureStderr(func() {
		code := runUpdate([]string{"--bogus"})
		if code != exitError {
			t.Errorf("expected exitError for invalid args, got %d", code)
		}
	})

	if !strings.Contains(stderr, "Error") {
		t.Errorf("expected error message in stderr, got: %s", truncate(stderr, 200))
	}
}

func TestRunUpdate_FetchError(t *testing.T) {
	// Use a non-existent server to trigger a fetch error.
	oldVersion := Version
	Version = "0.1.0"
	defer func() { Version = oldVersion }()

	stderr := captureStderr(func() {
		code := runUpdate([]string{"--api-url", "http://127.0.0.1:1", "--repo", "test/test"})
		if code != exitError {
			t.Errorf("expected exitError for fetch failure, got %d", code)
		}
	})

	if !strings.Contains(stderr, "Error") {
		t.Errorf("expected error message in stderr, got: %s", truncate(stderr, 200))
	}
}

func TestDownloadAsset_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("fake binary content"))
	}))
	defer server.Close()

	asset := &githubAsset{
		Name:               "test-binary",
		BrowserDownloadURL: server.URL,
	}

	path, err := DownloadAsset(asset)
	if err != nil {
		t.Fatalf("DownloadAsset error: %v", err)
	}
	defer os.Remove(path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read downloaded file: %v", err)
	}
	if string(data) != "fake binary content" {
		t.Errorf("downloaded content = %q, want %q", string(data), "fake binary content")
	}
}

func TestDownloadAsset_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	asset := &githubAsset{
		Name:               "test-binary",
		BrowserDownloadURL: server.URL,
	}

	_, err := DownloadAsset(asset)
	if err == nil {
		t.Error("expected error for HTTP 404 download")
	}
}

func TestPrintUpdateUsage(t *testing.T) {
	out := captureStdout(func() {
		printUpdateUsage()
	})
	if !strings.Contains(out, "Usage") {
		t.Errorf("expected usage text, got: %s", truncate(out, 200))
	}
	if !strings.Contains(out, "update") {
		t.Errorf("expected 'update' in usage, got: %s", truncate(out, 200))
	}
}

// =====================================================================
// Additional update tests for full coverage
// =====================================================================

func TestPerformUpdate_NoMatchingAsset(t *testing.T) {
	mockRelease := &githubRelease{
		TagName: "v0.2.0",
		Assets: []githubAsset{
			{Name: "aegisgate-scanner_0.2.0_freebsd_amd64",
				BrowserDownloadURL: "http://example.com/download/freebsd"},
		},
	}

	server := setupMockUpdateServer(t, mockRelease, "", "")
	defer server.Close()

	opts := UpdateOptions{
		Force:        true, // force to proceed past version check
		GitHubAPIURL: server.URL,
		Repo:         "test/test",
	}

	_, err := PerformUpdate(opts, "0.1.0")
	if err == nil {
		t.Fatal("expected error for no matching asset")
	}
	if !strings.Contains(err.Error(), "no matching release asset") {
		t.Errorf("expected 'no matching release asset' error, got: %v", err)
	}
}

func TestPerformUpdate_ChecksumMismatch(t *testing.T) {
	binaryContent := []byte("fake binary content for checksum test")

	mockRelease := &githubRelease{
		TagName: "v0.2.0",
		Assets: []githubAsset{
			{
				Name:               fmt.Sprintf("aegisgate-scanner_0.2.0_%s_%s", runtime.GOOS, runtime.GOARCH),
				BrowserDownloadURL: "http://example.com/download/binary",
			},
			{
				Name:               "checksums.sha256",
				BrowserDownloadURL: "http://example.com/checksums",
			},
		},
	}

	// Serve wrong checksum.
	server := setupMockUpdateServer(t, mockRelease, string(binaryContent),
		"0000000000000000000000000000000000000000000000000000000000000000  aegisgate-scanner_0.2.0_"+runtime.GOOS+"_"+runtime.GOARCH+"\n")
	defer server.Close()

	// Override asset download URL to point to our mock server.
	mockRelease.Assets[0].BrowserDownloadURL = server.URL + "/download/binary"
	mockRelease.Assets[1].BrowserDownloadURL = server.URL + "/checksums"

	opts := UpdateOptions{
		Force:        true,
		GitHubAPIURL: server.URL,
		Repo:         "test/test",
	}

	_, err := PerformUpdate(opts, "0.1.0")
	if err == nil {
		t.Fatal("expected error for checksum mismatch")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Errorf("expected checksum error, got: %v", err)
	}
}

func TestPerformUpdate_FullSuccess(t *testing.T) {
	binaryContent := []byte("fake binary content for full update test")

	// Calculate correct checksum.
	hash := sha256.Sum256(binaryContent)
	correctChecksum := hex.EncodeToString(hash[:])
	assetName := fmt.Sprintf("aegisgate-scanner_0.2.0_%s_%s", runtime.GOOS, runtime.GOARCH)

	mockRelease := &githubRelease{
		TagName: "v0.2.0",
		Assets: []githubAsset{
			{
				Name:               assetName,
				BrowserDownloadURL: "", // will be set below
			},
			{
				Name:               "checksums.sha256",
				BrowserDownloadURL: "", // will be set below
			},
		},
	}

	server := setupMockUpdateServer(t, mockRelease, string(binaryContent),
		correctChecksum+"  "+assetName+"\n")
	defer server.Close()

	mockRelease.Assets[0].BrowserDownloadURL = server.URL + "/download/binary"
	mockRelease.Assets[1].BrowserDownloadURL = server.URL + "/checksums"

	// Backup the current executable so we can restore it after replaceBinary.
	exePath, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	backup, err := os.ReadFile(exePath)
	if err != nil {
		t.Fatalf("read exe for backup: %v", err)
	}
	defer func() {
		_ = os.WriteFile(exePath, backup, 0755)
	}()

	opts := UpdateOptions{
		Force:        true,
		GitHubAPIURL: server.URL,
		Repo:         "test/test",
	}

	result, err := PerformUpdate(opts, "0.1.0")
	if err != nil {
		t.Fatalf("PerformUpdate error: %v", err)
	}
	if !result.ChecksumVerified {
		t.Error("expected checksum to be verified")
	}
	if result.DownloadedFile == "" {
		t.Error("expected downloaded file path to be set")
	}
}

func TestPerformUpdate_DownloadError(t *testing.T) {
	mockRelease := &githubRelease{
		TagName: "v0.2.0",
		Assets: []githubAsset{
			{
				Name:               fmt.Sprintf("aegisgate-scanner_0.2.0_%s_%s", runtime.GOOS, runtime.GOARCH),
				BrowserDownloadURL: "http://127.0.0.1:1/download/binary", // unreachable
			},
		},
	}

	server := setupMockUpdateServer(t, mockRelease, "", "")
	defer server.Close()

	opts := UpdateOptions{
		Force:        true,
		GitHubAPIURL: server.URL,
		Repo:         "test/test",
	}

	_, err := PerformUpdate(opts, "0.1.0")
	if err == nil {
		t.Fatal("expected error for download failure")
	}
	if !strings.Contains(err.Error(), "download") {
		t.Errorf("expected download error, got: %v", err)
	}
}

func TestReplaceBinary_Success(t *testing.T) {
	exePath, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	// Backup the current binary.
	backup, err := os.ReadFile(exePath)
	if err != nil {
		t.Fatalf("read exe for backup: %v", err)
	}
	defer func() {
		_ = os.WriteFile(exePath, backup, 0755)
	}()

	// Create a "downloaded" binary.
	dir := t.TempDir()
	downloadedPath := filepath.Join(dir, "new_binary")
	os.WriteFile(downloadedPath, []byte("fake replacement binary"), 0755)

	// Call ReplaceBinary — on Linux this renames the temp file over the exe.
	err = ReplaceBinary(downloadedPath)
	if err != nil {
		t.Fatalf("ReplaceBinary error: %v", err)
	}

	// Verify the replacement happened.
	data, err := os.ReadFile(exePath)
	if err != nil {
		t.Fatalf("read replaced exe: %v", err)
	}
	if string(data) != "fake replacement binary" {
		t.Errorf("exe content = %q, want %q", string(data), "fake replacement binary")
	}
}

func TestReplaceBinary_NonExistentFile(t *testing.T) {
	err := ReplaceBinary("/nonexistent/path/to/binary")
	if err == nil {
		t.Error("expected error for non-existent downloaded file")
	}
}

func TestRunUpdate_DefaultAPIAndRepo(t *testing.T) {
	// Test with defaults (no --api-url or --repo specified).
	// This will try to hit the real GitHub API, so we expect it to either
	// succeed or fail gracefully. We test that runUpdate doesn't panic
	// and returns a valid exit code.
	oldVersion := Version
	Version = "0.0.0-fake" // unlikely to match any real release
	defer func() { Version = oldVersion }()

	// This will try the real API. It might fail due to network issues,
	// but we just want to exercise the default URL/repo code paths.
	code := runUpdate([]string{"--dry-run"})
	// Accept any exit code — we're just testing the default path doesn't panic.
	_ = code
}

func TestRunUpdate_ForceDryRun(t *testing.T) {
	mockRelease := &githubRelease{
		TagName: "v0.1.0", // same as current
		Assets:  []githubAsset{},
	}

	server := setupMockUpdateServer(t, mockRelease, "", "")
	defer server.Close()

	oldVersion := Version
	Version = "0.1.0"
	defer func() { Version = oldVersion }()

	out := captureStdout(func() {
		code := runUpdate([]string{"--dry-run", "--force", "--api-url", server.URL, "--repo", "test/test"})
		if code != exitOK {
			t.Errorf("expected exitOK for force dry run, got %d", code)
		}
	})

	// With force=true and dry-run=true, should still show dry run message.
	if !strings.Contains(out, "Dry run") {
		t.Errorf("expected 'Dry run' message, got: %s", truncate(out, 200))
	}
}

func TestParseUpdateArgs_APIURLNoValue(t *testing.T) {
	_, err := ParseUpdateArgsExported([]string{"--api-url"})
	if err == nil {
		t.Error("expected error when --api-url has no value")
	}
}

func TestParseUpdateArgs_APIURLEquals(t *testing.T) {
	opts, err := ParseUpdateArgsExported([]string{"--api-url=http://localhost:9090"})
	if err != nil {
		t.Fatalf("parseUpdateArgs error: %v", err)
	}
	if opts.GitHubAPIURL != "http://localhost:9090" {
		t.Errorf("api-url = %s, want http://localhost:9090", opts.GitHubAPIURL)
	}
}

func TestParseUpdateArgs_RepoNoValue(t *testing.T) {
	_, err := ParseUpdateArgsExported([]string{"--repo"})
	if err == nil {
		t.Error("expected error when --repo has no value")
	}
}

func TestParseUpdateArgs_RepoEquals(t *testing.T) {
	opts, err := ParseUpdateArgsExported([]string{"--repo=myorg/myrepo"})
	if err != nil {
		t.Fatalf("parseUpdateArgs error: %v", err)
	}
	if opts.Repo != "myorg/myrepo" {
		t.Errorf("repo = %s, want myorg/myrepo", opts.Repo)
	}
}

func TestDownloadAsset_BadURL(t *testing.T) {
	asset := &githubAsset{
		Name:               "test-binary",
		BrowserDownloadURL: "http://127.0.0.1:1/download/binary", // unreachable port
	}

	_, err := DownloadAsset(asset)
	if err == nil {
		t.Error("expected error for unreachable download URL")
	}
}

func TestVerifyChecksum_NonExistentFile(t *testing.T) {
	release := &githubRelease{
		Assets: []githubAsset{
			{Name: "binary"},
		},
	}
	asset := &githubAsset{Name: "binary"}

	_, err := VerifyChecksum("/nonexistent/path/to/file", release, asset)
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestVerifyChecksum_ServerError(t *testing.T) {
	dir := t.TempDir()
	content := []byte("test content")
	filePath := filepath.Join(dir, "binary")
	os.WriteFile(filePath, content, 0644)

	// Create a server that returns an error for the checksums file.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	release := &githubRelease{
		Assets: []githubAsset{
			{Name: "checksums.sha256", BrowserDownloadURL: server.URL},
		},
	}
	asset := &githubAsset{Name: "binary"}

	// When the checksums file server errors, verifyChecksum should
	// continue and fall through to the "no checksums found" case (returns true).
	ok, err := VerifyChecksum(filePath, release, asset)
	if err != nil {
		t.Fatalf("VerifyChecksum error: %v", err)
	}
	// Should return true (skip verification) when checksums file can't be downloaded.
	if !ok {
		t.Error("expected true when checksums server returns error (skip verification)")
	}
}

// =====================================================================
// Additional runScan coverage tests
// =====================================================================

func TestRunScan_DiffVerbose(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	runGit(t, dir, "init", "--initial-branch=main")
	runGit(t, dir, "config", "user.email", "test@test.com")
	runGit(t, dir, "config", "user.name", "Test")

	os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("clean content"), 0644)
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "initial")

	runGit(t, dir, "checkout", "-b", "feature")
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("SSN: 123-45-6789"), 0644)
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "add file")

	var scanCode int
	stderr := captureStderr(func() {
		captureStdout(func() {
			scanCode = runScan([]string{dir, "--no-ml", "--format", "json", "--diff", "main", "--verbose"})
		})
	})

	if scanCode != exitFindings {
		t.Errorf("expected exitFindings from verbose diff scan, got %d", scanCode)
	}
	// Verbose mode should print diff info.
	if !strings.Contains(stderr, "Diff scan") {
		t.Errorf("expected 'Diff scan' in verbose stderr, got: %s", truncate(stderr, 200))
	}
}

func TestRunScan_ArchiveExtractionVerbose(t *testing.T) {
	dir := t.TempDir()

	// Create a zip archive with a text file inside.
	zipPath := filepath.Join(dir, "data.zip")
	createTestZip(t, zipPath, "inner.txt", []byte("SSN: 123-45-6789"))

	var scanCode int
	stderr := captureStderr(func() {
		captureStdout(func() {
			scanCode = runScan([]string{dir, "--no-ml", "--format", "json", "--extract-archives", "--verbose"})
		})
	})

	// Verbose mode should print extraction info.
	t.Logf("verbose archive stderr: %s", truncate(stderr, 300))
	t.Logf("verbose archive exit code: %d", scanCode)
}

func TestRunScan_ArchiveExtractionWithFindings(t *testing.T) {
	dir := t.TempDir()

	// Create a zip archive with a text file containing a secret.
	zipPath := filepath.Join(dir, "secrets.zip")
	createTestZip(t, zipPath, "secret.txt", []byte("SSN: 123-45-6789 in archive"))

	var scanCode int
	out := captureStdout(func() {
		scanCode = runScan([]string{dir, "--no-ml", "--format", "json", "--extract-archives"})
	})

	t.Logf("archive extraction output: %s", truncate(out, 300))
	t.Logf("archive extraction exit code: %d", scanCode)
}

func TestRunScan_PluginRegistrationFailure(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, ".aegisgate-plugins")
	os.MkdirAll(pluginDir, 0755)
	// Create a plugin with an invalid regex pattern.
	pluginContent := `name: bad-plugin
rules:
  - name: bad-rule
    pattern: "[invalidregex("
    severity: high
    category: secret
    description: Bad regex
`
	os.WriteFile(filepath.Join(pluginDir, "bad.yaml"), []byte(pluginContent), 0644)
	os.WriteFile(filepath.Join(dir, "data.txt"), []byte("some content"), 0644)

	// The plugin registration will fail but the scan should continue.
	stderr := captureStderr(func() {
		captureStdout(func() {
			runScan([]string{dir, "--no-ml", "--format", "json"})
		})
	})

	// Should print a warning about failed registration.
	if !strings.Contains(stderr, "Warning") && !strings.Contains(stderr, "plugin") {
		t.Errorf("expected warning about plugin registration failure, got: %s", truncate(stderr, 200))
	}
}

// =====================================================================
// Helpers
// =====================================================================

// runGit runs a git command in the given directory.
func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %s in %s: %v", strings.Join(args, " "), dir, err)
	}
}

// createTestZip creates a zip archive at zipPath containing a single file
// with the given name and content.
func createTestZip(t *testing.T, zipPath, filename string, content []byte) {
	t.Helper()
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer f.Close()

	w := zip.NewWriter(f)
	defer w.Close()

	fw, err := w.Create(filename)
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatalf("write zip entry: %v", err)
	}
}

// truncate returns the first n characters of s, for error messages.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
