// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — CLI Entry Point
// =========================================================================
//
// aegisgate-scanner — Antivirus for AI Artifacts
//
// Scans AI artifacts (RAG documents, training datasets, model configs,
// agent skills) for security threats before deployment. Detects prompt
// injection, PII, secrets, compliance violations, and more.
//
// Usage:
//   aegisgate-scanner scan [path] [flags]
//   aegisgate-scanner init
//   aegisgate-scanner version
//
// Output formats:
//   --format sarif   SARIF 2.1.0 (default for CI/CD)
//   --format json    Structured JSON
//   --format text    Human-readable text (default for terminal)
//
// Exit codes:
//   0 — No findings (scan passed)
//   1 — Findings detected (scan failed)
//   2 — Configuration or runtime error
//
// =========================================================================

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-scanner/internal/detectors"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/artifacts"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/baseline"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/cache"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/config"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/output"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/plugins"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/scanner"
)

// Version is set at build time via ldflags.
// The Makefile passes -ldflags="-X main.Version=$(VERSION)" using the
// VERSION file. When running via `go run` without ldflags, this default
// is used. Keep it in sync with the VERSION file.
var Version = "0.3.0"

// Exit codes.
const (
	exitOK       = 0
	exitFindings = 1
	exitError    = 2
)

func main() {
	os.Exit(run(os.Args))
}

// run dispatches CLI commands and returns the appropriate exit code.
// Extracted from main() so it can be unit-tested without os.Exit killing
// the test process.
func run(argv []string) int {
	if len(argv) < 2 {
		printUsage()
		return exitError
	}

	command := argv[1]
	args := argv[2:]

	// Parse global flags (--log-level, --log-format) before command dispatch.
	// These are available to all commands.
	logLevel := ""
	logFormat := ""
	args, logLevel, logFormat = parseGlobalFlags(args)

	// Initialize structured logger.
	// Precedence: CLI flag > default (info/text).
	// Config file values are applied later in each command after config load,
	// but we init here so even pre-config-load diagnostics are structured.
	if logLevel == "" {
		logLevel = "info"
	}
	if logFormat == "" {
		logFormat = "text"
	}
	initLogger(logLevel, logFormat)

	switch command {
	case "scan":
		return runScan(args, logLevel, logFormat)
	case "scan-history":
		return runScanHistory(args, logLevel, logFormat)
	case "init":
		return runInit(args)
	case "version":
		printVersion()
		return exitOK
	case "update":
		return runUpdate(args)
	case "doctor":
		return runDoctor(args)
	case "help", "--help", "-h":
		printUsage()
		return exitOK
	default:
		slog.Error("unknown command", "command", command)
		printUsage()
		return exitError
	}
}

// parseGlobalFlags scans args for --log-level and --log-format, removes
// them, and returns the remaining args along with the extracted values.
// This allows global flags to appear before or after command-specific args.
func parseGlobalFlags(args []string) (remaining []string, logLevel, logFormat string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch {
		case arg == "--log-level":
			i++
			if i < len(args) {
				logLevel = args[i]
			}

		case strings.HasPrefix(arg, "--log-level="):
			logLevel = strings.TrimPrefix(arg, "--log-level=")

		case arg == "--log-format":
			i++
			if i < len(args) {
				logFormat = args[i]
			}

		case strings.HasPrefix(arg, "--log-format="):
			logFormat = strings.TrimPrefix(arg, "--log-format=")

		default:
			remaining = append(remaining, arg)
		}
	}
	return remaining, logLevel, logFormat
}

// ---------------------------------------------------------------------
// scan command
// ---------------------------------------------------------------------

func runScan(args []string, globalLogLevel, globalLogFormat string) int {
	// Initialize logger early so even pre-config-parse errors are structured.
	// May be re-initialized later after config load with config-derived settings.
	earlyLevel := globalLogLevel
	if earlyLevel == "" {
		earlyLevel = "info"
	}
	earlyFormat := globalLogFormat
	if earlyFormat == "" {
		earlyFormat = "text"
	}
	initLogger(earlyLevel, earlyFormat)

	// Parse arguments.
	opts, err := parseScanArgs(args)
	if err != nil {
		slog.Error("failed to parse arguments", "error", err)
		printScanUsage()
		return exitError
	}

	// Handle stdin/pipe mode: path is "-"
	if opts.path == "-" {
		return runScanStdin(opts)
	}

	// Determine scan root.
	root := opts.path
	if root == "" {
		root = "."
	}

	// Resolve to absolute path.
	absRoot, err := filepath.Abs(root)
	if err != nil {
		slog.Error("cannot resolve path", "path", root, "error", err)
		return exitError
	}

	// Load configuration (merges defaults + .aegisgate.yml + CLI overrides).
	var cfg *config.Config
	if opts.configPath != "" {
		cfg, err = config.LoadFile(opts.configPath)
		if err != nil {
			slog.Error("configuration error", "config", opts.configPath, "error", err)
			return exitError
		}
	} else {
		cfg, err = config.Load(absRoot)
		if err != nil {
			slog.Error("configuration error", "error", err)
			return exitError
		}
	}

	// Apply CLI overrides.
	applyCLIOverrides(cfg, opts)

	// Reinitialize logger if config provides log settings and CLI didn't.
	// Precedence: CLI global flag > verbose shorthand > config file > default.
	// Note: --quiet only suppresses stdout output (scan results), not
	// diagnostic logging. This preserves the original semantics where
	// --verbose and --quiet were independent flags.
	effectiveLevel := globalLogLevel
	if effectiveLevel == "" || effectiveLevel == "info" {
		if opts.verbose {
			effectiveLevel = "debug"
		} else if cfg.LogLevel != "" && cfg.LogLevel != "info" {
			effectiveLevel = cfg.LogLevel
		}
	}
	effectiveFormat := globalLogFormat
	if effectiveFormat == "" || effectiveFormat == "text" {
		if cfg.LogFormat != "" && cfg.LogFormat != "text" {
			effectiveFormat = cfg.LogFormat
		}
	}
	initLogger(effectiveLevel, effectiveFormat)

	// Register custom rules from config.
	if len(cfg.CustomRules) > 0 {
		customDefs := cfg.ToDetectorPatterns()
		if err := detectors.RegisterCustomPatterns(customDefs); err != nil {
			slog.Error("invalid custom rule", "error", err)
			return exitError
		}
		slog.Debug("registered custom rules", "count", len(customDefs))
	}

	// Load and register plugins from .aegisgate-plugins/ directory.
	loadedPlugins, err := plugins.LoadPluginsFromDirWithDefault(absRoot)
	if err != nil {
		slog.Warn("failed to load plugins", "error", err)
	} else if len(loadedPlugins) > 0 {
		if err := plugins.RegisterPluginsWithDetector(loadedPlugins); err != nil {
			slog.Warn("failed to register plugins", "error", err)
		} else {
			totalRules := 0
			for _, p := range loadedPlugins {
				totalRules += len(p.Rules())
			}
			slog.Info("loaded plugins", "plugins", len(loadedPlugins), "rules", totalRules)
		}
	}

	// Walk files.
	walkResult, err := artifacts.Walk(cfg.ToWalkOptions(absRoot))
	if err != nil {
		slog.Error("file walk failed", "error", err)
		return exitError
	}

	// Apply diff scanning: filter to only changed files.
	if opts.diffBase != "" {
		changedFiles, err := scanner.GetChangedFiles(opts.diffBase, absRoot)
		if err != nil {
			slog.Error("git diff failed", "error", err)
			return exitError
		}
		slog.Info("diff scan", "changed_files", len(changedFiles), "base", opts.diffBase)

		// Filter artifacts to only changed files.
		var filteredArts []artifacts.Artifact
		changedSet := make(map[string]bool)
		for _, f := range changedFiles {
			changedSet[f] = true
		}
		for _, art := range walkResult.Artifacts {
			if changedSet[art.Path] {
				filteredArts = append(filteredArts, art)
			}
		}
		walkResult.Artifacts = filteredArts
	}

	// Apply archive extraction: extract archives and add extracted files.
	if opts.extractArchives {
		var newArts []artifacts.Artifact
		for _, art := range walkResult.Artifacts {
			if artifacts.IsArchive(art.AbsPath) {
				extResult, err := artifacts.ExtractArchive(art.AbsPath)
				if err != nil {
					slog.Warn("failed to extract archive", "path", art.Path, "error", err)
					newArts = append(newArts, art)
					continue
				}
				defer extResult.Cleanup()

				// Walk extracted directory.
				extWalkOpts := cfg.ToWalkOptions(extResult.Dir)
				extWalkOpts.RespectGitIgnore = false
				extWalkResult, err := artifacts.Walk(extWalkOpts)
				if err != nil {
					slog.Warn("failed to walk extracted archive", "path", art.Path, "error", err)
					newArts = append(newArts, art)
					continue
				}

				// Adjust paths to be relative to original archive.
				for i := range extWalkResult.Artifacts {
					extWalkResult.Artifacts[i].Path = art.Path + "!" + extWalkResult.Artifacts[i].Path
				}
				newArts = append(newArts, extWalkResult.Artifacts...)

				slog.Info("extracted archive", "files", len(extWalkResult.Artifacts), "archive", art.Path)
			} else {
				newArts = append(newArts, art)
			}
		}
		walkResult.Artifacts = newArts
	}

	// Skip if no artifacts found.
	if len(walkResult.Artifacts) == 0 {
		slog.Info("no supported AI artifacts found", "path", absRoot,
			"supported_extensions", strings.Join(artifacts.SupportedExtensions(), ", "))
		return exitOK
	}

	// Create scanner.
	scanOpts := cfg.ToScanOptions()

	// Apply concurrency override from CLI.
	if opts.concurrency > 0 {
		scanOpts.Concurrency = opts.concurrency
	}

	sc, err := scanner.New(scanOpts)
	if err != nil {
		slog.Error("scanner initialization failed", "error", err)
		return exitError
	}
	defer sc.Close()

	// Load ML model if enabled.
	if cfg.EnableML && cfg.ModelPath != "" {
		if err := sc.LoadModel(cfg.ModelPath); err != nil {
			// ML failure is non-fatal — fall back to regex-only.
			slog.Warn("ML model load failed, continuing with regex-only", "error", err)
		}
	} else if cfg.EnableML {
		// Try default model path.
		defaultPath := findDefaultModelPath()
		if defaultPath != "" {
			if err := sc.LoadModel(defaultPath); err != nil {
				slog.Warn("ML model load failed, continuing with regex-only", "error", err)
			}
		}
	}

	// Set up progress indicator for large scans (stderr, non-TTY safe).
	// Only show progress in text log mode — JSON log format would corrupt
	// structured log lines with carriage-return progress updates.
	if !opts.quiet && effectiveFormat == "text" && len(walkResult.Artifacts) > 10 {
		scanOpts.Progress = makeProgressFunc(os.Stderr, len(walkResult.Artifacts))
	}

	// Set up content-hash cache if enabled (via --cache flag or config).
	cacheEnabled := opts.cache || cfg.CacheEnabled
	if opts.clearCache {
		cachePath := opts.cacheDir
		if cachePath == "" {
			cachePath = cfg.CacheDir
		}
		if cachePath == "" {
			cachePath = filepath.Join(absRoot, ".aegisgate-cache.json")
		}
		if err := cache.Clear(cachePath); err != nil {
			slog.Error("failed to clear cache", "error", err)
			return exitError
		}
		slog.Info("cache cleared", "path", cachePath)
		return exitOK
	}

	var sc2 *cache.Cache
	if cacheEnabled {
		cachePath := opts.cacheDir
		if cachePath == "" {
			cachePath = cfg.CacheDir
		}
		if cachePath == "" {
			cachePath = filepath.Join(absRoot, ".aegisgate-cache.json")
		}
		header := scanner.ComputeCacheHeader(Version, cfg.EnableML)
		sc2, err = cache.Load(cachePath, header)
		if err != nil {
			slog.Warn("cache load failed, continuing without cache", "error", err)
		} else {
			// Apply eviction policy from config.
			sc2.MaxEntries = cfg.CacheMaxEntries
			if cfg.CacheMaxAge > 0 {
				sc2.MaxAge = time.Duration(cfg.CacheMaxAge) * time.Hour
			}
			// Evict any expired/excess entries from loaded cache.
			sc2.EvictNow()
			scanOpts.Cache = sc2
			slog.Info("cache enabled", "path", cachePath, "entries", sc2.EntryCount())
		}
	}

	// Scan artifacts.
	result := sc.ScanArtifacts(walkResult.Artifacts, scanOpts)

	// Save cache if it was used and has new entries.
	if sc2 != nil {
		hits, misses := sc2.Stats()
		slog.Info("cache stats", "hits", hits, "misses", misses)
		if err := sc2.Save(); err != nil {
			slog.Warn("cache save failed", "error", err)
		}
	}

	// Generate baseline mode: save current findings and exit.
	if opts.generateBaseline != "" {
		bl := baseline.FromScanResult(result)
		if err := bl.Save(opts.generateBaseline); err != nil {
			slog.Error("failed to save baseline", "error", err)
			return exitError
		}
		slog.Info("baseline saved", "path", opts.generateBaseline, "entries", len(bl.Entries))
		return exitOK
	}

	// Load and apply baseline suppression.
	if cfg.BaselinePath != "" {
		bl, err := baseline.Load(cfg.BaselinePath)
		if err != nil {
			slog.Error("failed to load baseline", "error", err)
			return exitError
		}
		filtered, suppressed := bl.Filter(result.Findings)
		result.Findings = filtered
		result.Stats.TotalFindings = len(filtered)
		if suppressed > 0 {
			slog.Info("suppressed findings via baseline", "count", suppressed)
		}
	}

	// Output results.
	if err := outputResults(result, absRoot, cfg, opts); err != nil {
		slog.Error("output failed", "error", err)
		return exitError
	}

	// Exit code based on fail-on-severity.
	if result.Stats.TotalFindings > 0 {
		failSeverity := cfg.FailOnSeverity
		if failSeverity == "" {
			failSeverity = "low"
		}
		// If fail-on is "low", any finding fails.
		// If fail-on is "high", only high+critical fail.
		rank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
		minRank, ok := rank[strings.ToLower(failSeverity)]
		if !ok {
			minRank = 1 // default: any finding fails
		}
		for _, f := range result.Findings {
			if r, ok := rank[strings.ToLower(string(f.Severity))]; ok && r >= minRank {
				return exitFindings
			}
		}
	}

	return exitOK
}

// ---------------------------------------------------------------------
// scan-history command
// ---------------------------------------------------------------------

func runScanHistory(args []string, globalLogLevel, globalLogFormat string) int {
	// Parse flags
	var (
		format     = "text"
		outputFile string
		maxCommits = 1000
		baseBranch string
		noMerge    = true
		sinceDate  string
		untilDate  string
	)

	// Simple flag parsing
	var positional []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format", "-f":
			if i+1 < len(args) {
				format = args[i+1]
				i++
			}
		case "--output", "-o":
			if i+1 < len(args) {
				outputFile = args[i+1]
				i++
			}
		case "--max-commits":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &maxCommits)
				i++
			}
		case "--base-branch":
			if i+1 < len(args) {
				baseBranch = args[i+1]
				i++
			}
		case "--include-merges":
			noMerge = false
		case "--since":
			if i+1 < len(args) {
				sinceDate = args[i+1]
				i++
			}
		case "--until":
			if i+1 < len(args) {
				untilDate = args[i+1]
				i++
			}
		case "--help", "-h":
			fmt.Fprint(os.Stderr, `Usage: aegisgate-scanner scan-history [repo-path] [flags]

Scan git commit history for secrets and sensitive data.

Flags:
  --format <fmt>       Output format: text, json, jsonl, sarif, html, sbom (default: text)
  --output <file>      Write output to file (default: stdout)
  --max-commits <n>    Maximum commits to scan (default: 1000)
  --base-branch <br>   Only scan commits not in this branch (e.g., "main")
  --include-merges     Include merge commits (default: skip)
  --since <date>       Only scan commits after this date (YYYY-MM-DD)
  --until <date>       Only scan commits before this date (YYYY-MM-DD)

Examples:
  aegisgate-scanner scan-history .
  aegisgate-scanner scan-history . --format json --output history.json
  aegisgate-scanner scan-history . --max-commits 500 --since 2026-01-01
`)
			return exitOK
		default:
			positional = append(positional, args[i])
		}
	}

	repoPath := "."
	if len(positional) > 0 {
		repoPath = positional[0]
	}

	// Resolve to absolute path
	absPath, err := filepath.Abs(repoPath)
	if err != nil {
		slog.Error("failed to resolve path", "path", repoPath, "error", err)
		return exitError
	}

	// Build history options
	opts := scanner.DefaultHistoryOptions()
	opts.MaxCommits = maxCommits
	opts.BaseBranch = baseBranch
	opts.IncludeMergeCommits = !noMerge

	if sinceDate != "" {
		t, err := time.Parse("2006-01-02", sinceDate)
		if err != nil {
			slog.Error("invalid --since date", "date", sinceDate, "error", err)
			return exitError
		}
		opts.Since = t
	}
	if untilDate != "" {
		t, err := time.Parse("2006-01-02", untilDate)
		if err != nil {
			slog.Error("invalid --until date", "date", untilDate, "error", err)
			return exitError
		}
		opts.Until = t
	}

	slog.Info("starting history scan", "repo", absPath, "max_commits", opts.MaxCommits)

	result, err := scanner.ScanHistory(absPath, opts)
	if err != nil {
		slog.Error("history scan failed", "error", err)
		return exitError
	}

	slog.Info("history scan complete",
		"commits_scanned", result.CommitsScanned,
		"commits_skipped", result.CommitsSkipped,
		"diffs_scanned", result.DiffsScanned,
		"findings", len(result.Findings),
		"elapsed", result.Elapsed.String(),
	)

	// Convert history findings to regular findings for output
	findings := make([]scanner.Finding, len(result.Findings))
	for i, hf := range result.Findings {
		findings[i] = hf.Finding
	}

	// Build a scan result for output formatting
	scanResult := &scanner.ScanResult{
		Findings: findings,
		Stats: scanner.ScanStats{
			FilesScanned:  result.DiffsScanned,
			TotalFindings: len(findings),
			BySeverity:    make(map[scanner.Severity]int),
			ByCategory:    make(map[string]int),
			ByLayer:       make(map[string]int),
		},
	}
	for _, f := range findings {
		scanResult.Stats.BySeverity[f.Severity]++
		scanResult.Stats.ByCategory[f.Category]++
		scanResult.Stats.ByLayer[f.DetectionLayer]++
	}

	// Format output
	var outBuf []byte
	switch format {
	case "json":
		outBuf, _ = output.FormatJSON(scanResult, absPath, Version)
	case "jsonl":
		outBuf, _ = output.FormatJSONL(scanResult, absPath, Version)
	case "sarif":
		outBuf, _ = output.FormatSARIF(scanResult, Version)
	case "html":
		outBuf, _ = output.FormatHTML(scanResult, absPath, Version)
	case "sbom":
		outBuf, _ = output.FormatSBOM(scanResult, absPath, Version)
	case "text":
		fallthrough
	default:
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Git History Scan Results\n"))
		sb.WriteString(fmt.Sprintf("=========================\n"))
		sb.WriteString(fmt.Sprintf("Commits scanned: %d\n", result.CommitsScanned))
		sb.WriteString(fmt.Sprintf("Commits skipped: %d\n", result.CommitsSkipped))
		sb.WriteString(fmt.Sprintf("Diffs scanned:   %d\n", result.DiffsScanned))
		sb.WriteString(fmt.Sprintf("Findings:        %d\n", len(result.Findings)))
		sb.WriteString(fmt.Sprintf("Elapsed:         %s\n\n", result.Elapsed))

		for _, hf := range result.Findings {
			commitShort := hf.CommitHash
			if len(commitShort) > 12 {
				commitShort = commitShort[:12]
			}
			sb.WriteString(fmt.Sprintf("[%s] %s\n", hf.Severity, hf.RuleID))
			sb.WriteString(fmt.Sprintf("  Commit: %s (%s)\n", commitShort, hf.CommitDate))
			sb.WriteString(fmt.Sprintf("  File:   %s:%d\n", hf.FilePath, hf.Line))
			sb.WriteString(fmt.Sprintf("  Match:  %s\n", truncateString(hf.MatchedText, 80)))
			sb.WriteString(fmt.Sprintf("  Remediation: %s\n\n", hf.Remediation))
		}
		outBuf = []byte(sb.String())
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, outBuf, 0644); err != nil {
			slog.Error("failed to write output", "file", outputFile, "error", err)
			return exitError
		}
		slog.Info("output written", "file", outputFile)
	} else {
		os.Stdout.Write(outBuf)
	}

	if len(findings) > 0 {
		return exitFindings
	}
	return exitOK
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// ---------------------------------------------------------------------
// init command
// ---------------------------------------------------------------------

func runInit(args []string) int {
	// Initialize logger (in case called directly in tests with redirected stderr).
	initLogger("info", "text")

	dir := "."
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		dir = args[0]
	}

	configPath := filepath.Join(dir, ".aegisgate.yml")

	// Create directory if it doesn't exist.
	if err := os.MkdirAll(dir, 0755); err != nil {
		slog.Error("cannot create directory", "dir", dir, "error", err)
		return exitError
	}

	// Check if file already exists.
	if _, err := os.Stat(configPath); err == nil {
		slog.Error("config file already exists", "path", configPath)
		return exitError
	}

	// Write default config.
	content := `# AegisGate Scanner Configuration
# https://aegisgatesecurity.io/docs/scanner

# Paths to ignore (glob patterns)
ignore_paths:
  - "*.git*"
  - "node_modules"
  - "vendor"
  - "dist"
  - "build"

# File extensions to scan (empty = all supported)
extensions: []

# Maximum file size to scan (bytes, default 10MB)
max_file_size: 10485760

# Follow symbolic links (default false)
follow_symlinks: false

# Minimum severity to report (critical, high, medium, low)
min_severity: low

# Enable ML threat detection (requires CGO build)
enable_ml: true

# ML detection threshold (0.0-1.0, default 0.50)
ml_threshold: 0.50

# Maximum findings per file (0 = unlimited)
max_findings_per_file: 0

# Output format: sarif, json, jsonl, text, html, pr-comment, github-actions, sbom
output_format: text

# Color output (text format only)
color_output: true

# Path to ONNX model file (empty = use bundled default)
model_path: ""

# Diagnostic log level: debug, info, warn, error
log_level: info

# Diagnostic log format: text, json
log_format: text
`

	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		slog.Error("cannot write config file", "path", configPath, "error", err)
		return exitError
	}

	fmt.Printf("Created %s\n", configPath)
	fmt.Println("Edit this file to customize scanner behavior.")
	return exitOK
}

// ---------------------------------------------------------------------
// version command
// ---------------------------------------------------------------------

func printVersion() {
	fmt.Printf("aegisgate-scanner %s\n", Version)
	fmt.Printf("  go: %s\n", runtime.Version())
	fmt.Printf("  platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  cgo: %v\n", isCGOEnabled())
}

// ---------------------------------------------------------------------
// doctor command — self-test / health check
// ---------------------------------------------------------------------

// runDoctor performs a self-test: scans the specified directory (or
// current directory), verifies the binary works, and reports a health
// summary. Useful for post-install verification, conference demos, and
// CI smoke tests.
func runDoctor(args []string) int {
	scanPath := "."
	if len(args) > 0 && args[0] != "" && !strings.HasPrefix(args[0], "-") {
		scanPath = args[0]
	}

	absPath, _ := filepath.Abs(scanPath)

	fmt.Printf("AegisGate Scanner v%s — Doctor\n", Version)
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println()

	// 1. Binary info
	fmt.Printf("📋 Binary\n")
	fmt.Printf("  version:  %s\n", Version)
	fmt.Printf("  go:       %s\n", runtime.Version())
	fmt.Printf("  platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  cgo:      %v\n", isCGOEnabled())
	fmt.Println()

	// 2. Config check
	fmt.Printf("⚙️  Configuration\n")
	cfg, err := config.Load(".")
	if err != nil {
		fmt.Printf("  ⚠️  config load: %v (using defaults)\n", err)
		cfg = config.Default()
	} else {
		fmt.Printf("  ✅ config loaded from .aegisgate.yml\n")
	}
	fmt.Printf("  output_format:  %s\n", cfg.OutputFormat)
	fmt.Printf("  min_severity:   %s\n", cfg.MinSeverity)
	fmt.Printf("  enable_ml:      %v\n", cfg.EnableML)
	fmt.Println()

	// 3. Self-scan
	fmt.Printf("🔍 Self-scan: %s\n", absPath)
	walkResult, err := artifacts.Walk(cfg.ToWalkOptions(absPath))
	if err != nil {
		fmt.Printf("  ❌ file walk failed: %v\n", err)
		return exitError
	}

	// Check if path exists.
	if _, statErr := os.Stat(absPath); statErr != nil {
		fmt.Printf("  ❌ path does not exist: %s\n", absPath)
		return exitError
	}

	scanOpts := cfg.ToScanOptions()
	sc, err := scanner.New(scanOpts)
	if err != nil {
		fmt.Printf("  ❌ scanner init failed: %v\n", err)
		return exitError
	}
	defer sc.Close()

	// Load ML model if enabled.
	if cfg.EnableML {
		defaultPath := findDefaultModelPath()
		if defaultPath != "" {
			if err := sc.LoadModel(defaultPath); err != nil {
				fmt.Printf("  ⚠️  ML model load failed: %v (continuing regex-only)\n", err)
			} else {
				fmt.Printf("  ✅ ML model loaded\n")
			}
		}
	}

	result := sc.ScanArtifacts(walkResult.Artifacts, scanOpts)

	fmt.Printf("  files scanned:     %d\n", result.Stats.FilesScanned)
	fmt.Printf("  files w/ findings: %d\n", result.Stats.FilesWithFindings)
	fmt.Printf("  total findings:    %d\n", result.Stats.TotalFindings)
	fmt.Printf("  duration:          %v\n", result.Duration)
	if result.Stats.CacheHits > 0 || result.Stats.CacheMisses > 0 {
		fmt.Printf("  cache hits:        %d\n", result.Stats.CacheHits)
		fmt.Printf("  cache misses:      %d\n", result.Stats.CacheMisses)
	}

	if len(result.Stats.BySeverity) > 0 {
		fmt.Printf("  by severity:       ")
		first := true
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			if count, ok := result.Stats.BySeverity[detectors.Severity(sev)]; ok && count > 0 {
				if !first {
					fmt.Printf(", ")
				}
				fmt.Printf("%s=%d", sev, count)
				first = false
			}
		}
		fmt.Println()
	}

	if len(result.Stats.ByCategory) > 0 {
		fmt.Printf("  by category:       ")
		cats := make([]string, 0, len(result.Stats.ByCategory))
		for cat := range result.Stats.ByCategory {
			cats = append(cats, cat)
		}
		sort.Strings(cats)
		for i, cat := range cats {
			if i > 0 {
				fmt.Printf(", ")
			}
			fmt.Printf("%s=%d", cat, result.Stats.ByCategory[cat])
		}
		fmt.Println()
	}

	if result.Stats.MLInferences > 0 {
		fmt.Printf("  ml inferences:     %d\n", result.Stats.MLInferences)
	}
	fmt.Println()

	// 4. Pattern counts
	fmt.Printf("🛡️  Detection Patterns\n")
	fmt.Printf("  secrets:             %d\n", len(detectors.SecretsPatterns))
	fmt.Printf("  pii-us-core:         %d\n", len(detectors.PIIUSCorePatterns))
	fmt.Printf("  pii-us-extended:     %d\n", len(detectors.PIIUSExtendedPatterns))
	fmt.Printf("  pii-financial:       %d\n", len(detectors.PIIFinancialPatterns))
	fmt.Printf("  pii-international:   %d\n", len(detectors.PIIInternationalPatterns))
	fmt.Printf("  dangerous-functions: %d\n", len(detectors.DangerousFunctionPatterns))
	fmt.Printf("  compliance:          %d\n", len(detectors.CompliancePatterns))
	fmt.Printf("  xss:                 %d\n", len(detectors.XSSPatterns))
	fmt.Printf("  ot-protocols:        %d\n", len(detectors.OTProtocolPatterns))

	totalPatterns := len(detectors.SecretsPatterns) + len(detectors.PIIUSCorePatterns) +
		len(detectors.PIIUSExtendedPatterns) + len(detectors.PIIFinancialPatterns) +
		len(detectors.PIIInternationalPatterns) + len(detectors.DangerousFunctionPatterns) +
		len(detectors.CompliancePatterns) + len(detectors.XSSPatterns) +
		len(detectors.OTProtocolPatterns)
	fmt.Printf("  total:               %d\n", totalPatterns)
	fmt.Println()

	// 5. Verdict
	fmt.Printf("✅ aegisgate-scanner is operational.\n")
	fmt.Printf("   Scanned %d files in %v with %d findings.\n",
		result.Stats.FilesScanned, result.Duration, result.Stats.TotalFindings)

	return exitOK
}

// ---------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------

// scanArgs holds parsed scan command arguments.
type scanArgs struct {
	path             string
	format           string
	output           string
	configPath       string
	minSeverity      string
	noML             bool
	noColor          bool
	quiet            bool
	verbose          bool
	baseline         string
	generateBaseline string
	concurrency      int
	failOn           string
	disableRules     []string
	stdinExt         string
	diffBase         string
	extractArchives  bool
	cache            bool
	cacheDir         string
	clearCache       bool
}

func parseScanArgs(args []string) (*scanArgs, error) {
	opts := &scanArgs{
		format: "", // will be set by config or default
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch {
		case arg == "--format" || arg == "-f":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--format requires a value")
			}
			opts.format = args[i]

		case arg == "--output" || arg == "-o":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--output requires a value")
			}
			opts.output = args[i]

		case arg == "--severity" || arg == "-s":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--severity requires a value")
			}
			opts.minSeverity = args[i]

		case arg == "--no-ml":
			opts.noML = true

		case arg == "--no-color":
			opts.noColor = true

		case arg == "--quiet" || arg == "-q":
			opts.quiet = true

		case arg == "--verbose" || arg == "-v":
			opts.verbose = true

		case arg == "--baseline":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--baseline requires a value")
			}
			opts.baseline = args[i]

		case strings.HasPrefix(arg, "--baseline="):
			opts.baseline = strings.TrimPrefix(arg, "--baseline=")

		case arg == "--generate-baseline":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--generate-baseline requires a value")
			}
			opts.generateBaseline = args[i]

		case strings.HasPrefix(arg, "--generate-baseline="):
			opts.generateBaseline = strings.TrimPrefix(arg, "--generate-baseline=")

		case arg == "--concurrency":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--concurrency requires a value")
			}
			n, err := strconv.Atoi(args[i])
			if err != nil || n < 0 {
				return nil, fmt.Errorf("--concurrency must be a non-negative integer")
			}
			opts.concurrency = n

		case strings.HasPrefix(arg, "--concurrency="):
			n, err := strconv.Atoi(strings.TrimPrefix(arg, "--concurrency="))
			if err != nil || n < 0 {
				return nil, fmt.Errorf("--concurrency must be a non-negative integer")
			}
			opts.concurrency = n

		case arg == "--fail-on":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--fail-on requires a value")
			}
			opts.failOn = args[i]

		case strings.HasPrefix(arg, "--fail-on="):
			opts.failOn = strings.TrimPrefix(arg, "--fail-on=")

		case arg == "--disable-rule":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--disable-rule requires a value")
			}
			opts.disableRules = append(opts.disableRules, args[i])

		case strings.HasPrefix(arg, "--disable-rule="):
			opts.disableRules = append(opts.disableRules, strings.TrimPrefix(arg, "--disable-rule="))

		case arg == "--stdin-ext":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--stdin-ext requires a value")
			}
			opts.stdinExt = args[i]

		case strings.HasPrefix(arg, "--stdin-ext="):
			opts.stdinExt = strings.TrimPrefix(arg, "--stdin-ext=")

		case arg == "--diff":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--diff requires a value")
			}
			opts.diffBase = args[i]

		case strings.HasPrefix(arg, "--diff="):
			opts.diffBase = strings.TrimPrefix(arg, "--diff=")

		case arg == "--extract-archives":
			opts.extractArchives = true

		case arg == "--no-extract-archives":
			opts.extractArchives = false

		case arg == "--cache":
			opts.cache = true

		case arg == "--no-cache":
			opts.cache = false

		case arg == "--cache-dir":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--cache-dir requires a value")
			}
			opts.cacheDir = args[i]

		case strings.HasPrefix(arg, "--cache-dir="):
			opts.cacheDir = strings.TrimPrefix(arg, "--cache-dir=")

		case arg == "--clear-cache":
			opts.clearCache = true

		case arg == "--config":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--config requires a value")
			}
			opts.configPath = args[i]

		case strings.HasPrefix(arg, "--config="):
			opts.configPath = strings.TrimPrefix(arg, "--config=")

		case strings.HasPrefix(arg, "--format="):
			opts.format = strings.TrimPrefix(arg, "--format=")

		case strings.HasPrefix(arg, "--output="):
			opts.output = strings.TrimPrefix(arg, "--output=")

		case strings.HasPrefix(arg, "--severity="):
			opts.minSeverity = strings.TrimPrefix(arg, "--severity=")

		case arg == "--help" || arg == "-h":
			printScanUsage()
			os.Exit(exitOK)

		case arg == "-":
			// "-" as path means read from stdin/pipe.
			if opts.path == "" {
				opts.path = "-"
			} else {
				return nil, fmt.Errorf("unexpected argument: %s", arg)
			}

		case !strings.HasPrefix(arg, "-"):
			if opts.path == "" {
				opts.path = arg
			} else {
				return nil, fmt.Errorf("unexpected argument: %s", arg)
			}

		default:
			return nil, fmt.Errorf("unknown flag: %s", arg)
		}
	}

	return opts, nil
}

// applyCLIOverrides applies CLI flag overrides to the config.
func applyCLIOverrides(cfg *config.Config, opts *scanArgs) {
	if opts.format != "" {
		cfg.OutputFormat = opts.format
	}
	if opts.minSeverity != "" {
		cfg.MinSeverity = opts.minSeverity
	}
	if opts.noML {
		cfg.EnableML = false
	}
	if opts.noColor {
		cfg.ColorOutput = false
	}
	if opts.baseline != "" {
		cfg.BaselinePath = opts.baseline
	}
	if opts.failOn != "" {
		cfg.FailOnSeverity = opts.failOn
	}
	if len(opts.disableRules) > 0 {
		cfg.DisableRules = append(cfg.DisableRules, opts.disableRules...)
	}
}

// ---------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------

func outputResults(result *scanner.ScanResult, root string, cfg *config.Config, opts *scanArgs) error {
	format := cfg.OutputFormat
	if format == "" {
		format = "text"
	}

	var data []byte
	var err error

	switch strings.ToLower(format) {
	case "sarif":
		data, err = output.FormatSARIF(result, Version)
		if err != nil {
			return fmt.Errorf("SARIF output: %w", err)
		}

	case "json":
		data, err = output.FormatJSON(result, root, Version)
		if err != nil {
			return fmt.Errorf("JSON output: %w", err)
		}

	case "jsonl":
		data, err = output.FormatJSONL(result, root, Version)
		if err != nil {
			return fmt.Errorf("JSONL output: %w", err)
		}

	case "html":
		data, err = output.FormatHTML(result, root, Version)
		if err != nil {
			return fmt.Errorf("HTML output: %w", err)
		}

	case "pr-comment":
		data, err = output.FormatPRComment(result, root, Version)
		if err != nil {
			return fmt.Errorf("PR comment output: %w", err)
		}

	case "github-actions":
		data, err = output.FormatGitHubActions(result, root, Version)
		if err != nil {
			return fmt.Errorf("GitHub Actions output: %w", err)
		}

	case "sbom":
		data, err = output.FormatSBOM(result, root, Version)
		if err != nil {
			return fmt.Errorf("SBOM output: %w", err)
		}

	case "text":
		text := output.FormatText(result, root, Version, cfg.ColorOutput)
		if opts.output != "" {
			return os.WriteFile(opts.output, []byte(text), 0644)
		}
		if !opts.quiet {
			fmt.Print(text)
		}
		return nil

	default:
		return fmt.Errorf("unknown output format: %s", format)
	}

	// Write to file or stdout for binary formats.
	if opts.output != "" {
		return os.WriteFile(opts.output, data, 0644)
	}

	// For SARIF/JSON, always output to stdout (these are machine-readable).
	fmt.Println(string(data))

	return nil
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// runScanStdin reads content from stdin, creates an artifact, and scans it.
// The file extension for classification is determined by --stdin-ext flag
// (defaults to .txt if not specified).
func runScanStdin(opts *scanArgs) int {
	// Initialize logger for stdin mode (in case runScan was called directly
	// in tests with redirected stderr).
	level := "info"
	if opts.verbose {
		level = "debug"
	}
	initLogger(level, "text")

	// Read all of stdin.
	content, err := io.ReadAll(os.Stdin)
	if err != nil {
		slog.Error("failed to read stdin", "error", err)
		return exitError
	}

	if len(content) == 0 {
		slog.Error("no content received on stdin")
		return exitError
	}

	// Determine file extension for classification.
	ext := opts.stdinExt
	if ext == "" {
		ext = ".txt"
	}
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}

	// Create artifact from stdin content.
	artPath := "stdin" + ext
	art := artifacts.ReadArtifactFromContent(artPath, content)

	if art.Binary {
		slog.Warn("stdin content appears to be binary")
	}

	// Load config from current directory.
	cfg, err := config.Load(".")
	if err != nil {
		slog.Error("configuration error", "error", err)
		return exitError
	}
	applyCLIOverrides(cfg, opts)

	// Register custom rules.
	if len(cfg.CustomRules) > 0 {
		customDefs := cfg.ToDetectorPatterns()
		if err := detectors.RegisterCustomPatterns(customDefs); err != nil {
			slog.Error("invalid custom rule", "error", err)
			return exitError
		}
	}

	// Create scanner.
	scanOpts := cfg.ToScanOptions()
	if opts.concurrency > 0 {
		scanOpts.Concurrency = opts.concurrency
	}

	sc, err := scanner.New(scanOpts)
	if err != nil {
		slog.Error("scanner initialization failed", "error", err)
		return exitError
	}
	defer sc.Close()

	// Load ML model if enabled.
	if cfg.EnableML {
		defaultPath := findDefaultModelPath()
		if cfg.ModelPath != "" {
			if err := sc.LoadModel(cfg.ModelPath); err != nil {
				slog.Warn("ML model load failed, continuing with regex-only", "error", err)
			}
		} else if defaultPath != "" {
			if err := sc.LoadModel(defaultPath); err != nil {
				slog.Warn("ML model load failed, continuing with regex-only", "error", err)
			}
		}
	}

	// Scan the single artifact.
	result := sc.ScanArtifacts([]artifacts.Artifact{art}, scanOpts)

	// Baseline handling.
	if opts.generateBaseline != "" {
		bl := baseline.FromScanResult(result)
		if err := bl.Save(opts.generateBaseline); err != nil {
			slog.Error("failed to save baseline", "error", err)
			return exitError
		}
		slog.Info("baseline saved", "path", opts.generateBaseline, "entries", len(bl.Entries))
		return exitOK
	}

	if cfg.BaselinePath != "" {
		bl, err := baseline.Load(cfg.BaselinePath)
		if err != nil {
			slog.Error("failed to load baseline", "error", err)
			return exitError
		}
		filtered, suppressed := bl.Filter(result.Findings)
		result.Findings = filtered
		result.Stats.TotalFindings = len(filtered)
		if suppressed > 0 {
			slog.Info("suppressed findings via baseline", "count", suppressed)
		}
	}

	// Output results.
	if err := outputResults(result, "stdin", cfg, opts); err != nil {
		slog.Error("output failed", "error", err)
		return exitError
	}

	// Exit code based on fail-on-severity.
	if result.Stats.TotalFindings > 0 {
		failSeverity := cfg.FailOnSeverity
		if failSeverity == "" {
			failSeverity = "low"
		}
		rank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
		minRank, ok := rank[strings.ToLower(failSeverity)]
		if !ok {
			minRank = 1
		}
		for _, f := range result.Findings {
			if r, ok := rank[strings.ToLower(string(f.Severity))]; ok && r >= minRank {
				return exitFindings
			}
		}
	}

	return exitOK
}

// makeProgressFunc creates a progress callback that writes to w.
// Shows "Scanning: N/M files" with a carriage return for in-place updates.
func makeProgressFunc(w io.Writer, total int) scanner.ProgressFunc {
	start := time.Now()
	lastUpdate := time.Time{}
	return func(scanned, totalFiles int) {
		// Throttle updates to every 500ms to avoid flooding.
		now := time.Now()
		if now.Sub(lastUpdate) < 500*time.Millisecond && scanned < totalFiles {
			return
		}
		lastUpdate = now

		elapsed := now.Sub(start).Round(time.Millisecond)
		fmt.Fprintf(w, "\rScanning: %d/%d files (%s)    ", scanned, totalFiles, elapsed)
		if scanned >= totalFiles {
			fmt.Fprintln(w) // newline after completion
		}
	}
}

// findDefaultModelPath searches for the bundled ONNX model file.
func findDefaultModelPath() string {
	candidates := []string{
		"models/threat_cnn_bilstm.onnx",
		"./models/threat_cnn_bilstm.onnx",
		"/app/models/threat_cnn_bilstm.onnx", // Docker
	}

	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// Check relative to executable.
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "models", "threat_cnn_bilstm.onnx")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ""
}

// isCGOEnabled is implemented via build tags in cgo_cgo.go and cgo_nocgo.go.

// ---------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------

func printUsage() {
	fmt.Print(`aegisgate-scanner — Antivirus for AI Artifacts

Usage:
  aegisgate-scanner <command> [options]

Commands:
  scan [path]         Scan a directory for security threats in AI artifacts
  scan-history [path] Scan git commit history for leaked secrets
  init [dir]          Create a .aegisgate.yml configuration file
  version             Print version information
  update              Check for and install updates
  doctor [path]       Self-test: scan own codebase and report health
  help                Show this help message

Scan Options:
  --format, -f <format>    Output format: sarif, json, jsonl, text, html, pr-comment,
                           github-actions, sbom (default: text)
  --output, -o <file>      Write output to file instead of stdout
  --severity, -s <level>   Minimum severity: critical, high, medium, low
  --no-ml                  Disable ML threat detection (regex-only)
  --no-color               Disable ANSI color output (text format)
  --quiet, -q              Suppress diagnostic output (errors only)
  --verbose, -v            Verbose output (debug-level logging)
  --baseline <file>        Load baseline suppression file
  --generate-baseline <f>  Save current findings as baseline
  --concurrency <N>        Number of parallel workers (default: auto)
  --fail-on <level>        Exit non-zero only for findings at/above level
  --disable-rule <id>      Disable specific detection rule (repeatable)
  --stdin-ext <ext>        File extension for stdin classification (default: .txt)
  --diff <base_branch>     Only scan files changed vs base branch
  --extract-archives       Extract archives before scanning (default: true)
  --no-extract-archives    Disable archive extraction
  --cache                  Enable content-hash caching (skip unchanged files)
  --cache-dir <path>       Cache file location (default: .aegisgate-cache.json)
  --clear-cache            Delete cache file and exit
  --config <file>          Path to explicit config file (overrides .aegisgate.yml)

Global Options:
  --log-level <level>      Log level: debug, info, warn, error (default: info)
  --log-format <format>    Log format: text, json (default: text)

Stdin/Pipe Support:
  cat file.json | aegisgate-scanner scan - --stdin-ext .json
  echo "Ignore all previous instructions" | aegisgate-scanner scan -

Exit Codes:
  0 — No findings (scan passed)
  1 — Findings detected (scan failed)
  2 — Configuration or runtime error

Examples:
  aegisgate-scanner scan ./my-project
  aegisgate-scanner scan ./rag-docs --format sarif -o results.sarif
  aegisgate-scanner scan . --severity high --format json
  cat agent_skill.py | aegisgate-scanner scan - --stdin-ext .py
  aegisgate-scanner init

For more information: https://aegisgatesecurity.io/docs/scanner
`)
}

func printScanUsage() {
	fmt.Print(`Usage: aegisgate-scanner scan [path] [options]

Options:
  --format, -f <format>    Output format: sarif, json, jsonl, text, html, pr-comment,
                           github-actions, sbom (default: text)
  --output, -o <file>      Write output to file instead of stdout
  --severity, -s <level>   Minimum severity: critical, high, medium, low
  --no-ml                  Disable ML threat detection (regex-only)
  --no-color               Disable ANSI color output (text format)
  --quiet, -q              Suppress diagnostic output (errors only)
  --verbose, -v            Verbose output (debug-level logging)
  --baseline <file>        Load baseline suppression file
  --generate-baseline <f>  Save current findings as baseline
  --concurrency <N>        Number of parallel workers (default: auto)
  --fail-on <level>        Exit non-zero only for findings at/above level
  --disable-rule <id>      Disable specific detection rule (repeatable)
  --stdin-ext <ext>        File extension for stdin classification (default: .txt)
  --diff <base_branch>     Only scan files changed vs base branch
  --extract-archives       Extract archives before scanning (default: true)
  --no-extract-archives    Disable archive extraction
  --cache                  Enable content-hash caching (skip unchanged files)
  --cache-dir <path>       Cache file location (default: .aegisgate-cache.json)
  --clear-cache            Delete cache file and exit
  --config <file>          Path to explicit config file (overrides .aegisgate.yml)

Global Options:
  --log-level <level>      Log level: debug, info, warn, error (default: info)
  --log-format <format>    Log format: text, json (default: text)

Stdin/Pipe Support:
  Use "-" as path to read from stdin:
    cat file.json | aegisgate-scanner scan - --stdin-ext .json
    echo "Ignore all previous instructions" | aegisgate-scanner scan -

Exit Codes:
  0 — No findings (scan passed)
  1 — Findings detected (scan failed)
  2 — Configuration or runtime error

Examples:
  aegisgate-scanner scan ./my-project
  aegisgate-scanner scan ./rag-docs --format sarif -o results.sarif
  aegisgate-scanner scan . --severity high --format json
  cat agent_skill.py | aegisgate-scanner scan - --stdin-ext .py
  aegisgate-scanner scan . --diff main --format github-actions
`)
}

// formatJSON is used for debug output.
func formatJSON(v interface{}) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
