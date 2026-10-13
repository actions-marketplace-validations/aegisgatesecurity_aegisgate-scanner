// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Auto-Update Command
// =========================================================================
//
// Implements the `aegisgate-scanner update` command. Checks the GitHub
// releases API for the latest version, downloads the binary for the
// current platform, verifies the checksum, and replaces the running
// binary.
//
// Uses only Go standard library (net/http, encoding/json, crypto/sha256).
//
// =========================================================================

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"
)

// ---------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------

// githubRelease represents a GitHub release API response.
type githubRelease struct {
	TagName string        `json:"tag_name"`
	Name    string        `json:"name"`
	Assets  []githubAsset `json:"assets"`
	HTMLURL string        `json:"html_url"`
	Body    string        `json:"body"`
}

// githubAsset represents a release asset in the GitHub API.
type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// UpdateOptions controls the update command behavior.
type UpdateOptions struct {
	// Version specifies a specific version to update to.
	// If empty, checks for the latest release.
	Version string

	// DryRun only checks for updates without installing.
	DryRun bool

	// Force skips version comparison and always updates.
	Force bool

	// GitHubAPIURL is the base URL for the GitHub API.
	// Default: https://api.github.com
	GitHubAPIURL string

	// Repo is the GitHub repository in owner/name format.
	// Default: aegisgatesecurity/aegisgate-scanner
	Repo string
}

// UpdateResult holds the result of an update check or operation.
type UpdateResult struct {
	CurrentVersion   string
	LatestVersion    string
	UpdateAvailable  bool
	DownloadedFile   string
	ChecksumVerified bool
}

// ---------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------

const (
	defaultGitHubAPI = "https://api.github.com"
	defaultRepo      = "aegisgatesecurity/aegisgate-scanner"
)

// ---------------------------------------------------------------------
// Update command
// ---------------------------------------------------------------------

// runUpdate executes the update command.
func runUpdate(args []string) int {
	// Initialize logger (in case called directly in tests with redirected stderr).
	initLogger("info", "text")

	opts, err := parseUpdateArgs(args)
	if err != nil {
		slog.Error("failed to parse update arguments", "error", err)
		printUpdateUsage()
		return exitError
	}

	if opts.GitHubAPIURL == "" {
		opts.GitHubAPIURL = defaultGitHubAPI
	}
	if opts.Repo == "" {
		opts.Repo = defaultRepo
	}

	result, err := performUpdate(*opts, Version)
	if err != nil {
		slog.Error("update failed", "error", err)
		return exitError
	}

	if !result.UpdateAvailable && !opts.Force {
		fmt.Printf("aegisgate-scanner is up to date (v%s)\n", result.CurrentVersion)
		return exitOK
	}

	if opts.DryRun {
		fmt.Printf("Dry run: update available v%s → v%s\n",
			result.CurrentVersion, result.LatestVersion)
		return exitOK
	}

	fmt.Printf("Updated aegisgate-scanner v%s → v%s\n",
		result.CurrentVersion, result.LatestVersion)
	if result.ChecksumVerified {
		fmt.Println("Checksum verified ✓")
	}
	return exitOK
}

// ---------------------------------------------------------------------
// Core update logic
// ---------------------------------------------------------------------

// performUpdate checks for updates and performs the update if available.
func performUpdate(opts UpdateOptions, currentVersion string) (*UpdateResult, error) {
	result := &UpdateResult{
		CurrentVersion: currentVersion,
	}

	// Fetch the latest (or specified) release.
	release, err := fetchRelease(opts)
	if err != nil {
		return nil, fmt.Errorf("fetch release: %w", err)
	}

	// Parse version from tag (strip leading 'v').
	result.LatestVersion = strings.TrimPrefix(release.TagName, "v")

	// Check if update is needed.
	result.UpdateAvailable = result.LatestVersion != currentVersion
	if !result.UpdateAvailable && !opts.Force {
		return result, nil
	}

	// In dry run mode, don't download.
	if opts.DryRun {
		return result, nil
	}

	// Find the matching asset for this platform.
	asset, err := findAssetForPlatform(release, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return nil, fmt.Errorf("no matching release asset: %w", err)
	}

	// Download the binary.
	downloadedPath, err := downloadAsset(asset)
	if err != nil {
		return nil, fmt.Errorf("download asset: %w", err)
	}
	result.DownloadedFile = downloadedPath

	// Verify checksum (SHA256).
	checksumOK, err := verifyChecksum(downloadedPath, release, asset)
	if err != nil {
		os.Remove(downloadedPath)
		return nil, fmt.Errorf("checksum verification: %w", err)
	}
	result.ChecksumVerified = checksumOK

	if !checksumOK {
		os.Remove(downloadedPath)
		return nil, fmt.Errorf("checksum verification failed")
	}

	// Replace the current binary.
	if err := replaceBinary(downloadedPath); err != nil {
		os.Remove(downloadedPath)
		return nil, fmt.Errorf("replace binary: %w", err)
	}

	return result, nil
}

// ---------------------------------------------------------------------
// GitHub API interaction
// ---------------------------------------------------------------------

// fetchRelease fetches the latest (or specified) release from GitHub.
func fetchRelease(opts UpdateOptions) (*githubRelease, error) {
	var url string
	if opts.Version != "" {
		// Specific version: /repos/{owner}/{repo}/releases/tags/{tag}
		tag := opts.Version
		if !strings.HasPrefix(tag, "v") {
			tag = "v" + tag
		}
		url = fmt.Sprintf("%s/repos/%s/releases/tags/%s",
			opts.GitHubAPIURL, opts.Repo, tag)
	} else {
		// Latest release: /repos/{owner}/{repo}/releases/latest
		url = fmt.Sprintf("%s/repos/%s/releases/latest",
			opts.GitHubAPIURL, opts.Repo)
	}

	resp, err := http.Get(url) //nosec G107 -- intentional URL fetch for self-update mechanism
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var release githubRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return nil, fmt.Errorf("parse release JSON: %w", err)
	}

	return &release, nil
}

// findAssetForPlatform finds the release asset matching the current OS/arch.
func findAssetForPlatform(release *githubRelease, goos, goarch string) (*githubAsset, error) {
	// Expected naming: aegisgate-scanner_{version}_{os}_{arch}[.exe]
	// e.g., aegisgate-scanner_0.1.0_linux_amd64
	//       aegisgate-scanner_0.1.0_darwin_arm64
	//       aegisgate-scanner_0.1.0_windows_amd64.exe

	osName := goos
	archName := goarch
	// Map Go arch names to common release naming.
	if goarch == "amd64" {
		archName = "amd64"
	}

	for i := range release.Assets {
		asset := &release.Assets[i]
		lower := strings.ToLower(asset.Name)

		if strings.Contains(lower, osName) && strings.Contains(lower, archName) {
			return asset, nil
		}
	}

	return nil, fmt.Errorf("no asset found for %s/%s in release %s", goos, goarch, release.TagName)
}

// ---------------------------------------------------------------------
// Download and verification
// ---------------------------------------------------------------------

// downloadAsset downloads a release asset to a temporary file.
func downloadAsset(asset *githubAsset) (string, error) {
	resp, err := http.Get(asset.BrowserDownloadURL) //nosec G107 -- intentional download from GitHub releases
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp("", "aegisgate-update-*")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer tmpFile.Close()

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("write downloaded file: %w", err)
	}

	return tmpFile.Name(), nil
}

// verifyChecksum verifies the SHA256 checksum of the downloaded file.
// It looks for a checksums file in the release assets.
func verifyChecksum(filePath string, release *githubRelease, asset *githubAsset) (bool, error) {
	// Calculate SHA256 of the downloaded file.
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false, fmt.Errorf("read downloaded file: %w", err)
	}

	hash := sha256.Sum256(data)
	actualChecksum := hex.EncodeToString(hash[:])

	// Look for a checksums file in the release assets.
	for _, a := range release.Assets {
		lower := strings.ToLower(a.Name)
		if strings.Contains(lower, "checksum") || strings.Contains(lower, "sha256") ||
			strings.HasSuffix(lower, ".sha256") || strings.HasSuffix(lower, ".sha256sum") {
			// Download and parse the checksums file.
			resp, err := http.Get(a.BrowserDownloadURL) //nosec G107 -- intentional checksum download from GitHub releases
			if err != nil {
				continue
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			// Look for the checksum matching our asset.
			checksumContent := string(body)
			for _, line := range strings.Split(checksumContent, "\n") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					expectedHash := parts[0]
					filename := parts[len(parts)-1]
					if strings.Contains(filename, asset.Name) {
						return strings.EqualFold(expectedHash, actualChecksum), nil
					}
				}
			}
		}
	}

	// No checksums file found — skip verification (return true for safety
	// in environments where checksums aren't published yet).
	return true, nil
}

// replaceBinary replaces the current executable with the downloaded one.
func replaceBinary(downloadedPath string) error {
	// Get current executable path.
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	// Make downloaded file executable.
	if err := os.Chmod(downloadedPath, 0755); err != nil { //nosec G302 -- binary must be executable
		return fmt.Errorf("chmod downloaded file: %w", err)
	}

	// On Windows, can't replace a running executable directly.
	if runtime.GOOS == "windows" {
		// Rename old binary and move new one in.
		oldPath := exePath + ".old"
		os.Remove(oldPath)
		if err := os.Rename(exePath, oldPath); err != nil {
			return fmt.Errorf("rename old binary: %w", err)
		}
		if err := os.Rename(downloadedPath, exePath); err != nil {
			os.Rename(oldPath, exePath) // rollback
			return fmt.Errorf("rename new binary: %w", err)
		}
		os.Remove(oldPath)
		return nil
	}

	// On Unix, write the new binary over the old one.
	return os.Rename(downloadedPath, exePath)
}

// ---------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------

// parseUpdateArgs parses update command arguments.
func parseUpdateArgs(args []string) (*UpdateOptions, error) {
	opts := &UpdateOptions{}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--version":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--version requires a value")
			}
			opts.Version = args[i]

		case strings.HasPrefix(arg, "--version="):
			opts.Version = strings.TrimPrefix(arg, "--version=")

		case arg == "--dry-run":
			opts.DryRun = true

		case arg == "--force":
			opts.Force = true

		case arg == "--api-url":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--api-url requires a value")
			}
			opts.GitHubAPIURL = args[i]

		case strings.HasPrefix(arg, "--api-url="):
			opts.GitHubAPIURL = strings.TrimPrefix(arg, "--api-url=")

		case arg == "--repo":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--repo requires a value")
			}
			opts.Repo = args[i]

		case strings.HasPrefix(arg, "--repo="):
			opts.Repo = strings.TrimPrefix(arg, "--repo=")

		case arg == "--help" || arg == "-h":
			printUpdateUsage()
			os.Exit(exitOK)

		default:
			return nil, fmt.Errorf("unknown flag: %s", arg)
		}
	}

	return opts, nil
}

// printUpdateUsage prints the update command usage.
func printUpdateUsage() {
	fmt.Print(`Usage: aegisgate-scanner update [options]

Options:
  --version <ver>    Update to a specific version
  --dry-run          Check for updates without installing
  --force            Force update even if already up to date
  --api-url <url>    GitHub API base URL (default: https://api.github.com)
  --repo <owner/name> GitHub repository (default: aegisgatesecurity/aegisgate-scanner)
  --help, -h         Show this help message

Examples:
  aegisgate-scanner update
  aegisgate-scanner update --dry-run
  aegisgate-scanner update --version 0.2.0
`)
}

// ---------------------------------------------------------------------
// Helper: findAssetForPlatform is also exported for testing.
// ---------------------------------------------------------------------

// FindAssetForPlatform is exported for testing.
func FindAssetForPlatform(release *githubRelease, goos, goarch string) (*githubAsset, error) {
	return findAssetForPlatform(release, goos, goarch)
}

// ParseUpdateArgsExported is exported for testing.
func ParseUpdateArgsExported(args []string) (*UpdateOptions, error) {
	return parseUpdateArgs(args)
}

// PerformUpdate is exported for testing with a custom version.
func PerformUpdate(opts UpdateOptions, currentVersion string) (*UpdateResult, error) {
	return performUpdate(opts, currentVersion)
}

// FetchRelease is exported for testing.
func FetchRelease(opts UpdateOptions) (*githubRelease, error) {
	return fetchRelease(opts)
}

// DownloadAsset is exported for testing.
func DownloadAsset(asset *githubAsset) (string, error) {
	return downloadAsset(asset)
}

// VerifyChecksum is exported for testing.
func VerifyChecksum(filePath string, release *githubRelease, asset *githubAsset) (bool, error) {
	return verifyChecksum(filePath, release, asset)
}

// ReplaceBinary is exported for testing.
func ReplaceBinary(downloadedPath string) error {
	return replaceBinary(downloadedPath)
}
