// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Artifact File Walker
// =========================================================================
//
// Walks directory trees and classifies files into AI artifact categories:
//   - RAG documents (.txt, .md, .rst, .html, .json, .jsonl, .csv, .xml)
//   - Training datasets (.jsonl, .csv, .json, .tsv)
//   - Model configs (.yaml, .yml, .json, .toml)
//   - Agent skills (.json, .yaml, .yml, .py, .ts, .js)
//
// Features:
//   - Extension-based classification with path-context disambiguation
//   - Binary file detection (null byte sampling)
//   - Symlink loop prevention
//   - Configurable maximum file size
//   - UTF-8 content reading with BOM stripping
//   - Gitignore-style path exclusion
//   - Line counting for precise location reporting
//
// =========================================================================

package artifacts

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// ---------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------

// ArtifactClass represents the category of AI artifact.
type ArtifactClass string

const (
	ClassRAGDocument  ArtifactClass = "rag-document"
	ClassTrainingData ArtifactClass = "training-data"
	ClassModelConfig  ArtifactClass = "model-config"
	ClassAgentSkill   ArtifactClass = "agent-skill"
	ClassGeneric      ArtifactClass = "generic"
)

// Artifact represents a single file identified for scanning.
type Artifact struct {
	// Path is the relative path from the scan root.
	Path string

	// AbsPath is the absolute filesystem path.
	AbsPath string

	// Class is the classified artifact type.
	Class ArtifactClass

	// Size is the file size in bytes.
	Size int64

	// Content is the file content read as UTF-8 text.
	// Empty if the file was skipped or is binary.
	Content string

	// Lines is the number of lines in the content.
	Lines int

	// Binary is true if the file was detected as binary.
	Binary bool

	// Skipped is the reason the file was skipped (empty if not skipped).
	Skipped string

	// ModTime is the file's modification time.
	ModTime int64
}

// WalkOptions controls the file walker behavior.
type WalkOptions struct {
	// Root is the root directory to scan.
	Root string

	// IgnorePaths are glob patterns to exclude (e.g., "*.git*", "vendor/").
	IgnorePaths []string

	// MaxFileSize is the maximum file size to read content from.
	// Files larger than this are skipped with a reason.
	// Default: 10 MB (10 * 1024 * 1024).
	MaxFileSize int64

	// FollowSymlinks controls whether symbolic links are followed.
	// Default: false (symlinks are skipped).
	FollowSymlinks bool

	// Extensions restricts scanning to specific file extensions.
	// If empty, all supported extensions are scanned.
	Extensions []string
}

// WalkResult holds the results of a directory walk.
type WalkResult struct {
	// Artifacts is the list of files to be scanned.
	Artifacts []Artifact

	// Skipped is the list of files that were skipped, with reasons.
	Skipped []Artifact

	// Stats holds summary statistics.
	Stats WalkStats
}

// WalkStats holds summary statistics from a walk.
type WalkStats struct {
	TotalFiles   int
	ScannedFiles int
	SkippedFiles int
	BinaryFiles  int
	TotalBytes   int64
	ByClass      map[ArtifactClass]int
}

// ---------------------------------------------------------------------
// Extension maps
// ---------------------------------------------------------------------

// supportedExtensions maps file extensions to their primary artifact class.
// Extensions that can map to multiple classes are resolved by path context.
var supportedExtensions = map[string][]ArtifactClass{
	".txt":   {ClassRAGDocument},
	".md":    {ClassRAGDocument},
	".rst":   {ClassRAGDocument},
	".html":  {ClassRAGDocument},
	".htm":   {ClassRAGDocument},
	".xml":   {ClassRAGDocument},
	".json":  {ClassRAGDocument, ClassTrainingData, ClassModelConfig, ClassAgentSkill},
	".jsonl": {ClassRAGDocument, ClassTrainingData},
	".csv":   {ClassRAGDocument, ClassTrainingData},
	".tsv":   {ClassTrainingData},
	".yaml":  {ClassModelConfig, ClassAgentSkill},
	".yml":   {ClassModelConfig, ClassAgentSkill},
	".toml":  {ClassModelConfig},
	".py":    {ClassAgentSkill},
	".ts":    {ClassAgentSkill},
	".js":    {ClassAgentSkill},
}

// pathContextKeywords maps path substrings to artifact classes for
// disambiguation when an extension matches multiple classes.
var pathContextKeywords = []struct {
	Keywords []string
	Class    ArtifactClass
}{
	{[]string{"skill", "tool", "agent"}, ClassAgentSkill},
	{[]string{"config", "model", "settings"}, ClassModelConfig},
	{[]string{"train", "dataset", "corpus", "eval"}, ClassTrainingData},
	{[]string{"rag", "knowledge", "docs", "documents"}, ClassRAGDocument},
}

// defaultMaxFileSize is the default maximum file size (10 MB).
const defaultMaxFileSize = 10 * 1024 * 1024

// binaryCheckBytes is the number of bytes to sample for binary detection.
const binaryCheckBytes = 512

// ---------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------

// ClassifyFile determines the artifact class for a file based on its
// extension and path context.
func ClassifyFile(path string) ArtifactClass {
	ext := strings.ToLower(filepath.Ext(path))

	classes, ok := supportedExtensions[ext]
	if !ok {
		return ClassGeneric
	}

	// Single-class extensions return directly.
	if len(classes) == 1 {
		return classes[0]
	}

	// Multi-class extensions use path context for disambiguation.
	lowerPath := strings.ToLower(path)
	for _, ctx := range pathContextKeywords {
		for _, kw := range ctx.Keywords {
			if strings.Contains(lowerPath, kw) {
				return ctx.Class
			}
		}
	}

	// Default to the first class for multi-class extensions.
	return classes[0]
}

// IsSupportedExtension returns true if the file extension is in the
// supported set for AI artifact scanning.
func IsSupportedExtension(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	_, ok := supportedExtensions[ext]
	return ok
}

// SupportedExtensions returns all supported file extensions.
func SupportedExtensions() []string {
	exts := make([]string, 0, len(supportedExtensions))
	for ext := range supportedExtensions {
		exts = append(exts, ext)
	}
	sort.Strings(exts)
	return exts
}

// ---------------------------------------------------------------------
// Binary detection
// ---------------------------------------------------------------------

// isBinary checks whether a file contains binary data by sampling the
// first binaryCheckBytes bytes for null bytes or a high proportion of
// non-text bytes.
func isBinary(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("open file for binary check: %w", err)
	}
	defer f.Close()

	buf := make([]byte, binaryCheckBytes)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return false, fmt.Errorf("read file for binary check: %w", err)
	}
	buf = buf[:n]

	// Null byte → binary.
	for _, b := range buf {
		if b == 0 {
			return true, nil
		}
	}

	// Check for high proportion of non-text bytes.
	// Text bytes: printable ASCII (0x09-0x0D, 0x20-0x7E) + valid UTF-8.
	nonText := 0
	for _, b := range buf {
		if b < 0x09 || (b > 0x0D && b < 0x20) {
			nonText++
		}
	}

	// If more than 30% non-text bytes in the sample, treat as binary.
	if n > 0 && nonText*100/n > 30 {
		return true, nil
	}

	return false, nil
}

// ---------------------------------------------------------------------
// Content reading
// ---------------------------------------------------------------------

// readContent reads file content as UTF-8 text, stripping any BOM.
// Returns the content and the number of lines.
func readContent(path string, maxBytes int64) (string, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	// Limit reading to maxBytes to prevent memory exhaustion.
	reader := bufio.NewReader(f)

	var sb strings.Builder
	buf := make([]byte, 32*1024)
	totalRead := int64(0)

	for {
		if maxBytes > 0 && totalRead >= maxBytes {
			break
		}
		n, err := reader.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
			totalRead += int64(n)
		}
		if err != nil {
			break
		}
	}

	content := sb.String()

	// Strip UTF-8 BOM if present.
	content = strings.TrimPrefix(content, "\xEF\xBB\xBF")

	// Count lines.
	lines := strings.Count(content, "\n")
	if len(content) > 0 && !strings.HasSuffix(content, "\n") {
		lines++ // count the last line if it doesn't end with newline
	}

	return content, lines, nil
}

// ---------------------------------------------------------------------
// Ignore pattern matching
// ---------------------------------------------------------------------

// shouldIgnore checks if a path matches any ignore pattern.
// Patterns support:
//   - Exact path matches (e.g., ".git")
//   - Glob patterns (e.g., "*.log", "vendor/*")
//   - Directory names (e.g., "node_modules" matches any path containing it)
func shouldIgnore(path string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}

	// Normalize path separators.
	normalized := filepath.ToSlash(path)
	parts := strings.Split(normalized, "/")

	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" || strings.HasPrefix(pattern, "#") {
			continue
		}

		// Check if any path component matches the pattern.
		for _, part := range parts {
			matched, err := filepath.Match(pattern, part)
			if err == nil && matched {
				return true
			}
		}

		// Check full path glob match.
		matched, err := filepath.Match(pattern, normalized)
		if err == nil && matched {
			return true
		}

		// Check prefix match for directory patterns (e.g., "vendor/").
		if strings.HasSuffix(pattern, "/") {
			prefix := strings.TrimSuffix(pattern, "/")
			for _, part := range parts {
				if part == prefix {
					return true
				}
			}
		}

		// Check substring match for simple patterns.
		if !strings.Contains(pattern, "*") && !strings.Contains(pattern, "?") {
			if strings.Contains(normalized, pattern) {
				return true
			}
		}
	}

	return false
}

// defaultIgnorePaths are always ignored.
var defaultIgnorePaths = []string{
	".git",
	".svn",
	".hg",
	"node_modules",
	"__pycache__",
	".pytest_cache",
	".mypy_cache",
	".ruff_cache",
	"dist",
	"build",
	"bin",
	"vendor",
	".venv",
	"venv",
	"env",
	".env",
	".idea",
	".vscode",
	".DS_Store",
	"*.pyc",
	"*.pyo",
	"*.class",
	"*.o",
	"*.a",
	"*.so",
	"*.dylib",
	"*.dll",
	"*.exe",
	"*.woff",
	"*.woff2",
	"*.ttf",
	"*.eot",
	"*.png",
	"*.jpg",
	"*.jpeg",
	"*.gif",
	"*.webp",
	"*.ico",
	"*.svg",
	"*.pdf",
	"*.zip",
	"*.tar",
	"*.gz",
	"*.bz2",
	"*.7z",
	"*.rar",
	"*.parquet",
	"*.feather",
	"*.onnx",
	"*.pt",
	"*.pth",
	"*.bin",
	"*.safetensors",
}

// ---------------------------------------------------------------------
// Walk
// ---------------------------------------------------------------------

// Walk traverses the directory tree rooted at opts.Root and returns
// classified artifacts ready for scanning.
func Walk(opts WalkOptions) (*WalkResult, error) {
	if opts.Root == "" {
		return nil, fmt.Errorf("walk root cannot be empty")
	}

	// Normalize root path.
	root, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, fmt.Errorf("resolve root path: %w", err)
	}

	// Apply defaults.
	maxFileSize := opts.MaxFileSize
	if maxFileSize <= 0 {
		maxFileSize = defaultMaxFileSize
	}

	// Merge ignore paths: defaults + user-specified.
	ignorePatterns := make([]string, 0, len(defaultIgnorePaths)+len(opts.IgnorePaths))
	ignorePatterns = append(ignorePatterns, defaultIgnorePaths...)
	ignorePatterns = append(ignorePatterns, opts.IgnorePaths...)

	// Build extension filter set.
	extFilter := make(map[string]bool)
	for _, ext := range opts.Extensions {
		extFilter[strings.ToLower(ext)] = true
	}

	// Track visited inodes to prevent symlink loops. Shared across all
	// recursive walkInternal calls so loops are detected at any depth.
	visited := make(map[uint64]bool)

	return walkInternal(opts, root, ignorePatterns, maxFileSize, extFilter, visited)
}

// walkInternal performs the actual directory walk with a shared visited map
// for symlink loop detection across recursive calls.
func walkInternal(
	opts WalkOptions,
	root string,
	ignorePatterns []string,
	maxFileSize int64,
	extFilter map[string]bool,
	visited map[uint64]bool,
) (*WalkResult, error) {
	result := &WalkResult{
		Stats: WalkStats{
			ByClass: make(map[ArtifactClass]int),
		},
	}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// If we can't access a path, skip it rather than aborting.
			result.Skipped = append(result.Skipped, Artifact{
				Path:    relPath(root, path),
				AbsPath: path,
				Skipped: fmt.Sprintf("access error: %v", err),
			})
			result.Stats.SkippedFiles++
			return nil
		}

		rel := relPath(root, path)

		// Skip ignored paths.
		if shouldIgnore(rel, ignorePatterns) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Handle symlinks (to directories or files).
		if d.Type()&fs.ModeSymlink != 0 {
			if !opts.FollowSymlinks {
				// Check if it's a symlink to a directory.
				info, err := os.Stat(path)
				if err != nil {
					return nil // skip broken symlinks silently
				}
				if info.IsDir() {
					// Return nil, NOT SkipDir. SkipDir on a non-directory entry
					// (symlinks are non-directory for WalkDir) would skip all
					// remaining siblings in the containing directory.
					return nil
				}
				result.Skipped = append(result.Skipped, Artifact{
					Path:    rel,
					AbsPath: path,
					Skipped: "symlink (followSymlinks=false)",
				})
				result.Stats.SkippedFiles++
				return nil
			}

			// FollowSymlinks=true: check target type and handle loops.
			info, err := os.Stat(path)
			if err != nil {
				return nil // skip broken symlinks silently
			}
			if info.IsDir() {
				stat, ok := getInode(info)
				if ok && visited[stat] {
					return nil // loop detected, skip this entry
				}
				if ok {
					visited[stat] = true
				}

				// Resolve the real target path so the recursive walk starts at
				// a real directory, not a symlink. This prevents the symlink
				// handler from firing again on the root of the sub-walk.
				realPath, err := filepath.EvalSymlinks(path)
				if err != nil {
					return nil // can't resolve, skip
				}

				// Walk the resolved target with the same visited map.
				subResult, err := walkInternal(opts, realPath, ignorePatterns, maxFileSize, extFilter, visited)
				if err != nil {
					return nil
				}

				// Adjust paths to be relative to the original root.
				for i := range subResult.Artifacts {
					subPath := subResult.Artifacts[i].Path
					subResult.Artifacts[i].Path = filepath.ToSlash(filepath.Join(rel, subPath))
					subResult.Artifacts[i].AbsPath = filepath.Join(path, subPath)
				}
				for i := range subResult.Skipped {
					subPath := subResult.Skipped[i].Path
					subResult.Skipped[i].Path = filepath.ToSlash(filepath.Join(rel, subPath))
					subResult.Skipped[i].AbsPath = filepath.Join(path, subPath)
				}
				result.Artifacts = append(result.Artifacts, subResult.Artifacts...)
				result.Skipped = append(result.Skipped, subResult.Skipped...)
				result.Stats.TotalFiles += subResult.Stats.TotalFiles
				result.Stats.ScannedFiles += subResult.Stats.ScannedFiles
				result.Stats.SkippedFiles += subResult.Stats.SkippedFiles
				result.Stats.BinaryFiles += subResult.Stats.BinaryFiles
				result.Stats.TotalBytes += subResult.Stats.TotalBytes
				for k, v := range subResult.Stats.ByClass {
					result.Stats.ByClass[k] += v
				}
				return nil
			}
			// Symlink to a file with FollowSymlinks=true: fall through to file handling.
		}

		// Handle regular directories.
		if d.IsDir() {
			return nil
		}

		result.Stats.TotalFiles++

		// Get file info.
		info, err := d.Info()
		if err != nil {
			result.Skipped = append(result.Skipped, Artifact{
				Path:    rel,
				AbsPath: path,
				Skipped: fmt.Sprintf("stat error: %v", err),
			})
			result.Stats.SkippedFiles++
			return nil
		}

		// Check extension.
		ext := strings.ToLower(filepath.Ext(path))
		if !IsSupportedExtension(path) {
			return nil // silently skip unsupported extensions
		}

		// Apply extension filter if specified.
		if len(extFilter) > 0 && !extFilter[ext] {
			return nil
		}

		// Check file size.
		if info.Size() > maxFileSize {
			result.Skipped = append(result.Skipped, Artifact{
				Path:    rel,
				AbsPath: path,
				Size:    info.Size(),
				Skipped: fmt.Sprintf("file too large (%d bytes > %d max)", info.Size(), maxFileSize),
			})
			result.Stats.SkippedFiles++
			return nil
		}

		// Check for binary content.
		binary, err := isBinary(path)
		if err != nil {
			result.Skipped = append(result.Skipped, Artifact{
				Path:    rel,
				AbsPath: path,
				Skipped: fmt.Sprintf("binary check error: %v", err),
			})
			result.Stats.SkippedFiles++
			return nil
		}

		if binary {
			result.Skipped = append(result.Skipped, Artifact{
				Path:    rel,
				AbsPath: path,
				Size:    info.Size(),
				Binary:  true,
				Skipped: "binary file",
			})
			result.Stats.BinaryFiles++
			result.Stats.SkippedFiles++
			return nil
		}

		// Read content.
		content, lines, err := readContent(path, maxFileSize)
		if err != nil {
			result.Skipped = append(result.Skipped, Artifact{
				Path:    rel,
				AbsPath: path,
				Size:    info.Size(),
				Skipped: fmt.Sprintf("read error: %v", err),
			})
			result.Stats.SkippedFiles++
			return nil
		}

		// Skip empty files.
		if len(content) == 0 {
			result.Skipped = append(result.Skipped, Artifact{
				Path:    rel,
				AbsPath: path,
				Size:    info.Size(),
				Skipped: "empty file",
			})
			result.Stats.SkippedFiles++
			return nil
		}

		// Classify.
		class := ClassifyFile(path)

		artifact := Artifact{
			Path:    rel,
			AbsPath: path,
			Class:   class,
			Size:    info.Size(),
			Content: content,
			Lines:   lines,
			ModTime: info.ModTime().Unix(),
		}

		result.Artifacts = append(result.Artifacts, artifact)
		result.Stats.ScannedFiles++
		result.Stats.TotalBytes += info.Size()
		result.Stats.ByClass[class]++

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walk directory: %w", err)
	}

	return result, nil
}

// relPath returns the path relative to root, or the path itself if the
// calculation fails.
func relPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}

// getInode extracts the inode number from file info for symlink loop detection.
// Returns 0, false on platforms that don't support inodes.
func getInode(info fs.FileInfo) (uint64, bool) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Ino, true
	}
	return 0, false
}
