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
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-scanner/internal/detectors"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/artifacts"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/baseline"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/config"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/output"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/plugins"
	"github.com/aegisgatesecurity/aegisgate-scanner/pkg/scanner"
)

// Version is set at build time via ldflags.
var Version = "0.1.0-dev"

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

	switch command {
	case "scan":
		return runScan(args)
	case "init":
		return runInit(args)
	case "version":
		printVersion()
		return exitOK
	case "update":
		return runUpdate(args)
	case "help", "--help", "-h":
		printUsage()
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		return exitError
	}
}

// ---------------------------------------------------------------------
// scan command
// ---------------------------------------------------------------------

func runScan(args []string) int {
	// Parse arguments.
	opts, err := parseScanArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
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
		fmt.Fprintf(os.Stderr, "Error: cannot resolve path %s: %v\n", root, err)
		return exitError
	}

	// Load configuration (merges defaults + .aegisgate.yml + CLI overrides).
	cfg, err := config.Load(absRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: configuration error: %v\n", err)
		return exitError
	}

	// Apply CLI overrides.
	applyCLIOverrides(cfg, opts)

	// Register custom rules from config.
	if len(cfg.CustomRules) > 0 {
		customDefs := cfg.ToDetectorPatterns()
		if err := detectors.RegisterCustomPatterns(customDefs); err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid custom rule: %v\n", err)
			return exitError
		}
		if opts.verbose {
			fmt.Fprintf(os.Stderr, "Registered %d custom rules\n", len(customDefs))
		}
	}

	// Load and register plugins from .aegisgate-plugins/ directory.
	loadedPlugins, err := plugins.LoadPluginsFromDirWithDefault(absRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load plugins: %v\n", err)
	} else if len(loadedPlugins) > 0 {
		if err := plugins.RegisterPluginsWithDetector(loadedPlugins); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to register plugins: %v\n", err)
		} else if opts.verbose {
			totalRules := 0
			for _, p := range loadedPlugins {
				totalRules += len(p.Rules())
			}
			fmt.Fprintf(os.Stderr, "Loaded %d plugins with %d rules\n", len(loadedPlugins), totalRules)
		}
	}

	// Walk files.
	walkResult, err := artifacts.Walk(cfg.ToWalkOptions(absRoot))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: file walk failed: %v\n", err)
		return exitError
	}

	// Apply diff scanning: filter to only changed files.
	if opts.diffBase != "" {
		changedFiles, err := scanner.GetChangedFiles(opts.diffBase, absRoot)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: git diff failed: %v\n", err)
			return exitError
		}
		if opts.verbose {
			fmt.Fprintf(os.Stderr, "Diff scan: %d changed files vs %s\n", len(changedFiles), opts.diffBase)
		}

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
					if opts.verbose {
						fmt.Fprintf(os.Stderr, "Warning: failed to extract %s: %v\n", art.Path, err)
					}
					newArts = append(newArts, art)
					continue
				}
				defer extResult.Cleanup()

				// Walk extracted directory.
				extWalkOpts := cfg.ToWalkOptions(extResult.Dir)
				extWalkOpts.RespectGitIgnore = false
				extWalkResult, err := artifacts.Walk(extWalkOpts)
				if err != nil {
					if opts.verbose {
						fmt.Fprintf(os.Stderr, "Warning: failed to walk extracted %s: %v\n", art.Path, err)
					}
					newArts = append(newArts, art)
					continue
				}

				// Adjust paths to be relative to original archive.
				for i := range extWalkResult.Artifacts {
					extWalkResult.Artifacts[i].Path = art.Path + "!" + extWalkResult.Artifacts[i].Path
				}
				newArts = append(newArts, extWalkResult.Artifacts...)

				if opts.verbose {
					fmt.Fprintf(os.Stderr, "Extracted %d files from %s\n", len(extWalkResult.Artifacts), art.Path)
				}
			} else {
				newArts = append(newArts, art)
			}
		}
		walkResult.Artifacts = newArts
	}

	// Skip if no artifacts found.
	if len(walkResult.Artifacts) == 0 {
		fmt.Fprintf(os.Stderr, "No supported AI artifacts found in %s\n", absRoot)
		fmt.Fprintf(os.Stderr, "Supported extensions: %s\n",
			strings.Join(artifacts.SupportedExtensions(), ", "))
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
		fmt.Fprintf(os.Stderr, "Error: scanner initialization failed: %v\n", err)
		return exitError
	}
	defer sc.Close()

	// Load ML model if enabled.
	if cfg.EnableML && cfg.ModelPath != "" {
		if err := sc.LoadModel(cfg.ModelPath); err != nil {
			// ML failure is non-fatal — fall back to regex-only.
			fmt.Fprintf(os.Stderr, "Warning: ML model load failed: %v (continuing with regex-only)\n", err)
		}
	} else if cfg.EnableML {
		// Try default model path.
		defaultPath := findDefaultModelPath()
		if defaultPath != "" {
			if err := sc.LoadModel(defaultPath); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: ML model load failed: %v (continuing with regex-only)\n", err)
			}
		}
	}

	// Set up progress indicator for large scans (stderr, non-TTY safe).
	if !opts.quiet && len(walkResult.Artifacts) > 10 {
		scanOpts.Progress = makeProgressFunc(os.Stderr, len(walkResult.Artifacts))
	}

	// Scan artifacts.
	result := sc.ScanArtifacts(walkResult.Artifacts, scanOpts)

	// Generate baseline mode: save current findings and exit.
	if opts.generateBaseline != "" {
		bl := baseline.FromScanResult(result)
		if err := bl.Save(opts.generateBaseline); err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to save baseline: %v\n", err)
			return exitError
		}
		fmt.Fprintf(os.Stderr, "Baseline saved to %s (%d entries)\n", opts.generateBaseline, len(bl.Entries))
		return exitOK
	}

	// Load and apply baseline suppression.
	if cfg.BaselinePath != "" {
		bl, err := baseline.Load(cfg.BaselinePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to load baseline: %v\n", err)
			return exitError
		}
		filtered, suppressed := bl.Filter(result.Findings)
		result.Findings = filtered
		result.Stats.TotalFindings = len(filtered)
		if suppressed > 0 && opts.verbose {
			fmt.Fprintf(os.Stderr, "Suppressed %d findings via baseline\n", suppressed)
		}
	}

	// Output results.
	if err := outputResults(result, absRoot, cfg, opts); err != nil {
		fmt.Fprintf(os.Stderr, "Error: output failed: %v\n", err)
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
// init command
// ---------------------------------------------------------------------

func runInit(args []string) int {
	dir := "."
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		dir = args[0]
	}

	configPath := filepath.Join(dir, ".aegisgate.yml")

	// Create directory if it doesn't exist.
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot create directory %s: %v\n", dir, err)
		return exitError
	}

	// Check if file already exists.
	if _, err := os.Stat(configPath); err == nil {
		fmt.Fprintf(os.Stderr, "Error: %s already exists\n", configPath)
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

# Output format: sarif, json, text
output_format: text

# Color output (text format only)
color_output: true

# Path to ONNX model file (empty = use bundled default)
model_path: ""
`

	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot write %s: %v\n", configPath, err)
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
// Argument parsing
// ---------------------------------------------------------------------

// scanArgs holds parsed scan command arguments.
type scanArgs struct {
	path             string
	format           string
	output           string
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
	// Read all of stdin.
	content, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to read stdin: %v\n", err)
		return exitError
	}

	if len(content) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no content received on stdin\n")
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
		fmt.Fprintf(os.Stderr, "Warning: stdin content appears to be binary\n")
	}

	// Load config from current directory.
	cfg, err := config.Load(".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: configuration error: %v\n", err)
		return exitError
	}
	applyCLIOverrides(cfg, opts)

	// Register custom rules.
	if len(cfg.CustomRules) > 0 {
		customDefs := cfg.ToDetectorPatterns()
		if err := detectors.RegisterCustomPatterns(customDefs); err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid custom rule: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "Error: scanner initialization failed: %v\n", err)
		return exitError
	}
	defer sc.Close()

	// Load ML model if enabled.
	if cfg.EnableML {
		defaultPath := findDefaultModelPath()
		if cfg.ModelPath != "" {
			if err := sc.LoadModel(cfg.ModelPath); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: ML model load failed: %v (continuing with regex-only)\n", err)
			}
		} else if defaultPath != "" {
			if err := sc.LoadModel(defaultPath); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: ML model load failed: %v (continuing with regex-only)\n", err)
			}
		}
	}

	// Scan the single artifact.
	result := sc.ScanArtifacts([]artifacts.Artifact{art}, scanOpts)

	// Baseline handling.
	if opts.generateBaseline != "" {
		bl := baseline.FromScanResult(result)
		if err := bl.Save(opts.generateBaseline); err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to save baseline: %v\n", err)
			return exitError
		}
		fmt.Fprintf(os.Stderr, "Baseline saved to %s (%d entries)\n", opts.generateBaseline, len(bl.Entries))
		return exitOK
	}

	if cfg.BaselinePath != "" {
		bl, err := baseline.Load(cfg.BaselinePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to load baseline: %v\n", err)
			return exitError
		}
		filtered, suppressed := bl.Filter(result.Findings)
		result.Findings = filtered
		result.Stats.TotalFindings = len(filtered)
		if suppressed > 0 && opts.verbose {
			fmt.Fprintf(os.Stderr, "Suppressed %d findings via baseline\n", suppressed)
		}
	}

	// Output results.
	if err := outputResults(result, "stdin", cfg, opts); err != nil {
		fmt.Fprintf(os.Stderr, "Error: output failed: %v\n", err)
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
  scan [path]    Scan a directory for security threats in AI artifacts
  init [dir]     Create a .aegisgate.yml configuration file
  version        Print version information
  update         Check for and install updates
  help           Show this help message

Scan Options:
  --format, -f <format>    Output format: sarif, json, text, html, pr-comment,
                           github-actions, sbom (default: text)
  --output, -o <file>      Write output to file instead of stdout
  --severity, -s <level>   Minimum severity: critical, high, medium, low
  --no-ml                  Disable ML threat detection (regex-only)
  --no-color               Disable ANSI color output (text format)
  --quiet, -q              Suppress output (exit code only)
  --verbose, -v            Verbose output
  --baseline <file>        Load baseline suppression file
  --generate-baseline <f>  Save current findings as baseline
  --concurrency <N>        Number of parallel workers (default: auto)
  --fail-on <level>        Exit non-zero only for findings at/above level
  --disable-rule <id>      Disable specific detection rule (repeatable)
  --stdin-ext <ext>        File extension for stdin classification (default: .txt)
  --diff <base_branch>     Only scan files changed vs base branch
  --extract-archives       Extract archives before scanning (default: true)
  --no-extract-archives    Disable archive extraction

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
  --format, -f <format>    Output format: sarif, json, text, html, pr-comment,
                           github-actions, sbom (default: text)
  --output, -o <file>      Write output to file instead of stdout
  --severity, -s <level>   Minimum severity: critical, high, medium, low
  --no-ml                  Disable ML threat detection (regex-only)
  --no-color               Disable ANSI color output (text format)
  --quiet, -q              Suppress output (exit code only)
  --verbose, -v            Verbose output
  --baseline <file>        Load baseline suppression file
  --generate-baseline <f>  Save current findings as baseline
  --concurrency <N>        Number of parallel workers (default: auto)
  --fail-on <level>        Exit non-zero only for findings at/above level
  --disable-rule <id>      Disable specific detection rule (repeatable)
  --stdin-ext <ext>        File extension for stdin classification (default: .txt)
  --diff <base_branch>     Only scan files changed vs base branch
  --extract-archives       Extract archives before scanning (default: true)
  --no-extract-archives    Disable archive extraction

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
