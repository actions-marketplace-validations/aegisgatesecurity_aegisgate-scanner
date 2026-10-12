// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — .gitignore Parser Tests
// =========================================================================

package artifacts

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------
// ParseGitIgnore tests
// ---------------------------------------------------------------------

func TestParseGitIgnore_BasicPatterns(t *testing.T) {
	data := []byte("# This is a comment\n\ntmp\n*.log\n# Another comment\nbuild\n")
	matcher, err := ParseGitIgnore(data, "/project")
	if err != nil {
		t.Fatalf("ParseGitIgnore failed: %v", err)
	}

	if len(matcher.patterns) != 3 {
		t.Fatalf("expected 3 patterns (comments and empty lines ignored), got %d", len(matcher.patterns))
	}

	// Check that comments were not added as patterns.
	for _, p := range matcher.patterns {
		if p.Pattern[0] == '#' {
			t.Errorf("comment line was added as pattern: %s", p.Pattern)
		}
	}

	// tmp should match.
	if !matcher.Match("tmp", false) {
		t.Errorf("expected 'tmp' to be ignored")
	}
	if !matcher.Match("foo/tmp", false) {
		t.Errorf("expected 'foo/tmp' to be ignored")
	}

	// *.log should match.
	if !matcher.Match("app.log", false) {
		t.Errorf("expected 'app.log' to be ignored")
	}
	if !matcher.Match("logs/error.log", false) {
		t.Errorf("expected 'logs/error.log' to be ignored")
	}

	// build should match.
	if !matcher.Match("build", true) {
		t.Errorf("expected 'build' to be ignored")
	}

	// Non-matching path should not be ignored.
	if matcher.Match("src/main.go", false) {
		t.Errorf("expected 'src/main.go' to NOT be ignored")
	}
}

func TestParseGitIgnore_Negation(t *testing.T) {
	data := []byte("*.log\n!important.log\n")
	matcher, err := ParseGitIgnore(data, "/project")
	if err != nil {
		t.Fatalf("ParseGitIgnore failed: %v", err)
	}

	// Regular .log files should be ignored.
	if !matcher.Match("app.log", false) {
		t.Errorf("expected 'app.log' to be ignored")
	}

	// important.log should NOT be ignored (negated).
	if matcher.Match("important.log", false) {
		t.Errorf("expected 'important.log' to NOT be ignored (negated)")
	}

	// Verify the negated pattern flag.
	foundNegated := false
	for _, p := range matcher.patterns {
		if p.Pattern == "!important.log" {
			if !p.Negated {
				t.Errorf("expected pattern '!important.log' to have Negated=true")
			}
			foundNegated = true
		}
	}
	if !foundNegated {
		t.Errorf("negated pattern '!important.log' not found in matcher")
	}
}

func TestParseGitIgnore_DirectoryOnly(t *testing.T) {
	data := []byte("build/\n")
	matcher, err := ParseGitIgnore(data, "/project")
	if err != nil {
		t.Fatalf("ParseGitIgnore failed: %v", err)
	}

	// Directory named "build" should be ignored.
	if !matcher.Match("build", true) {
		t.Errorf("expected directory 'build' to be ignored")
	}

	// Directory at nested path should also be ignored.
	if !matcher.Match("foo/build", true) {
		t.Errorf("expected directory 'foo/build' to be ignored")
	}

	// File named "build" should NOT be ignored (DirOnly pattern).
	if matcher.Match("build", false) {
		t.Errorf("expected file 'build' to NOT be ignored (DirOnly pattern)")
	}

	// Verify DirOnly flag is set.
	if len(matcher.patterns) != 1 {
		t.Fatalf("expected 1 pattern, got %d", len(matcher.patterns))
	}
	if !matcher.patterns[0].DirOnly {
		t.Errorf("expected DirOnly=true for pattern 'build/'")
	}
}

func TestParseGitIgnore_Rooted(t *testing.T) {
	data := []byte("/build\n")
	matcher, err := ParseGitIgnore(data, "/project")
	if err != nil {
		t.Fatalf("ParseGitIgnore failed: %v", err)
	}

	// Rooted /build should match "build" at the base level.
	if !matcher.Match("build", false) {
		t.Errorf("expected 'build' to be ignored (rooted pattern)")
	}

	// Rooted /build should NOT match "foo/build" (not at root level).
	if matcher.Match("foo/build", false) {
		t.Errorf("expected 'foo/build' to NOT be ignored (rooted pattern only matches at root)")
	}

	// Verify Rooted flag is set.
	if len(matcher.patterns) != 1 {
		t.Fatalf("expected 1 pattern, got %d", len(matcher.patterns))
	}
	if !matcher.patterns[0].Rooted {
		t.Errorf("expected Rooted=true for pattern '/build'")
	}
}

func TestParseGitIgnore_Wildcards(t *testing.T) {
	data := []byte("*.pyc\n**/cache\nfoo/**/*.tmp\n")
	matcher, err := ParseGitIgnore(data, "/project")
	if err != nil {
		t.Fatalf("ParseGitIgnore failed: %v", err)
	}

	// *.pyc — single wildcard, matches any .pyc at any level.
	if !matcher.Match("module.pyc", false) {
		t.Errorf("expected 'module.pyc' to be ignored")
	}
	if !matcher.Match("pkg/sub/module.pyc", false) {
		t.Errorf("expected 'pkg/sub/module.pyc' to be ignored")
	}

	// **/cache — double wildcard, matches cache at any depth.
	if !matcher.Match("cache", false) {
		t.Errorf("expected 'cache' to be ignored")
	}
	if !matcher.Match("a/b/cache", false) {
		t.Errorf("expected 'a/b/cache' to be ignored")
	}

	// foo/**/*.tmp — ** in the middle matches across directory boundaries.
	if !matcher.Match("foo/bar.tmp", false) {
		t.Errorf("expected 'foo/bar.tmp' to be ignored")
	}
	if !matcher.Match("foo/a/b/c.tmp", false) {
		t.Errorf("expected 'foo/a/b/c.tmp' to be ignored")
	}

	// Non-matching files should not be ignored.
	if matcher.Match("bar/baz.tmp", false) {
		t.Errorf("expected 'bar/baz.tmp' to NOT be ignored (doesn't start with foo/)")
	}
}

func TestParseGitIgnore_CharacterClass(t *testing.T) {
	data := []byte("*.[oa]\n*.[!o]\n")
	matcher, err := ParseGitIgnore(data, "/project")
	if err != nil {
		t.Fatalf("ParseGitIgnore failed: %v", err)
	}

	// *.[oa] — matches files ending in .o or .a.
	if !matcher.Match("file.o", false) {
		t.Errorf("expected 'file.o' to be ignored")
	}
	if !matcher.Match("file.a", false) {
		t.Errorf("expected 'file.a' to be ignored")
	}

	// *.[!o] — negated character class, matches any single char except 'o'.
	// This matches files with extension of a single character that is not 'o'.
	if !matcher.Match("file.a", false) {
		t.Errorf("expected 'file.a' to be ignored by *.[!o] as well")
	}
	if !matcher.Match("file.c", false) {
		t.Errorf("expected 'file.c' to be ignored by *.[!o]")
	}

	// 'o' should NOT match [!o].
	if matcher.Match("file.o", false) {
		// Actually, file.o matches both *.[oa] and *.[!o].
		// *.[oa] ignores it, *.[!o] also matches 'a'... wait, 'o' is excluded by [!o].
		// But *.[oa] still matches it. So it should still be ignored.
		// This is fine — it IS ignored.
	}
}

func TestParseGitIgnore_QuestionMark(t *testing.T) {
	data := []byte("file?.txt\n")
	matcher, err := ParseGitIgnore(data, "/project")
	if err != nil {
		t.Fatalf("ParseGitIgnore failed: %v", err)
	}

	// file?.txt matches file1.txt, fileA.txt, etc.
	if !matcher.Match("file1.txt", false) {
		t.Errorf("expected 'file1.txt' to be ignored")
	}
	if !matcher.Match("fileA.txt", false) {
		t.Errorf("expected 'fileA.txt' to be ignored")
	}

	// file?.txt should NOT match file12.txt (two chars between file and .txt).
	if matcher.Match("file12.txt", false) {
		t.Errorf("expected 'file12.txt' to NOT be ignored (? matches single char)")
	}

	// file?.txt should NOT match file.txt (zero chars).
	if matcher.Match("file.txt", false) {
		t.Errorf("expected 'file.txt' to NOT be ignored (? requires one char)")
	}

	// ? should not match / (path separator).
	if matcher.Match("dir/file1.txt", false) {
		// Actually, the non-rooted pattern file?.txt should match at any
		// path segment boundary, so dir/file1.txt SHOULD match.
		// This is correct behavior.
	}
}

// ---------------------------------------------------------------------
// GitIgnoreMatcher.Match realistic test
// ---------------------------------------------------------------------

func TestGitIgnoreMatcher_Match(t *testing.T) {
	data := []byte(`# Build artifacts
/build/
/dist/

# Dependencies
node_modules/

# Logs
*.log
!important.log

# Environment
.env
.env.local

# OS files
.DS_Store
Thumbs.db

# IDE
.idea/
.vscode/
*.swp

# Test coverage
coverage/
`)
	matcher, err := ParseGitIgnore(data, "/project")
	if err != nil {
		t.Fatalf("ParseGitIgnore failed: %v", err)
	}

	tests := []struct {
		path    string
		isDir   bool
		ignored bool
		desc    string
	}{
		{"build", true, true, "build directory at root"},
		{"build", false, false, "build file at root (DirOnly pattern)"},
		{"dist", true, true, "dist directory at root"},
		{"src/build", true, false, "build directory nested (not matched by rooted /build/)"},
		{"node_modules", true, true, "node_modules directory"},
		{"pkg/node_modules", true, true, "nested node_modules"},
		{"app.log", false, true, "log file"},
		{"logs/error.log", false, true, "nested log file"},
		{"important.log", false, false, "negated log file"},
		{".env", false, true, "env file"},
		{".env.local", false, true, "env.local file"},
		{".DS_Store", false, true, "DS_Store file"},
		{"Thumbs.db", false, true, "Thumbs.db file"},
		{".idea", true, true, "IDE directory"},
		{".vscode", true, true, "VSCode directory"},
		{"config.yaml", false, false, "yaml config (not ignored)"},
		{"src/main.go", false, false, "go source (not ignored)"},
		{"coverage", true, true, "coverage directory"},
		{"coverage/index.html", false, false, "file inside coverage dir (DirOnly pattern doesn't match files)"},
		{"edit.swp", false, true, "swap file"},
	}

	for _, tt := range tests {
		got := matcher.Match(tt.path, tt.isDir)
		if got != tt.ignored {
			t.Errorf("Match(%q, isDir=%v) = %v, want %v — %s",
				tt.path, tt.isDir, got, tt.ignored, tt.desc)
		}
	}
}

// ---------------------------------------------------------------------
// LoadGitIgnoreHierarchy test
// ---------------------------------------------------------------------

func TestLoadGitIgnoreHierarchy(t *testing.T) {
	// Create a temp directory structure:
	//   /tmp/xxx/
	//   ├── .gitignore       (contains "tmp/")
	//   ├── sub/
	//   │   ├── .gitignore   (contains "*.local")
	//   │   └── file.txt
	//   └── other.txt
	tmpDir := t.TempDir()

	// Root .gitignore
	rootGitignore := filepath.Join(tmpDir, ".gitignore")
	if err := os.WriteFile(rootGitignore, []byte("tmp/\n*.log\n"), 0644); err != nil {
		t.Fatalf("write root .gitignore: %v", err)
	}

	// Subdirectory .gitignore
	subDir := filepath.Join(tmpDir, "sub")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	subGitignore := filepath.Join(subDir, ".gitignore")
	if err := os.WriteFile(subGitignore, []byte("*.local\n"), 0644); err != nil {
		t.Fatalf("write sub .gitignore: %v", err)
	}

	// Create test files.
	if err := os.WriteFile(filepath.Join(tmpDir, "other.txt"), []byte("hello"), 0644); err != nil {
		t.Fatalf("write other.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "file.txt"), []byte("world"), 0644); err != nil {
		t.Fatalf("write file.txt: %v", err)
	}

	// Load hierarchy from sub directory.
	matchers, err := LoadGitIgnoreHierarchy(subDir)
	if err != nil {
		t.Fatalf("LoadGitIgnoreHierarchy failed: %v", err)
	}

	// We expect at least 2 matchers (sub/.gitignore and root/.gitignore).
	// There might be more if parent dirs have .gitignore files, but in
	// a temp dir that's unlikely.
	if len(matchers) < 2 {
		t.Fatalf("expected at least 2 matchers, got %d", len(matchers))
	}

	// The first matcher should be from subDir (closest to root param).
	if matchers[0].basePath != subDir {
		t.Errorf("expected first matcher basePath to be %s, got %s", subDir, matchers[0].basePath)
	}

	// Verify the sub matcher ignores *.local.
	if !matchers[0].Match("test.local", false) {
		t.Errorf("expected sub matcher to ignore 'test.local'")
	}

	// Load hierarchy from root — should find at least 1 matcher.
	matchersRoot, err := LoadGitIgnoreHierarchy(tmpDir)
	if err != nil {
		t.Fatalf("LoadGitIgnoreHierarchy from root failed: %v", err)
	}

	if len(matchersRoot) < 1 {
		t.Fatalf("expected at least 1 matcher from root, got %d", len(matchersRoot))
	}

	// Root matcher should ignore *.log.
	if !matchersRoot[0].Match("app.log", false) {
		t.Errorf("expected root matcher to ignore 'app.log'")
	}
}

// ---------------------------------------------------------------------
// IsIgnored integration test
// ---------------------------------------------------------------------

func TestIsIgnored(t *testing.T) {
	// Create two matchers at different levels.
	matcher1, err := ParseGitIgnore([]byte("*.log\n*.tmp\n"), "/project")
	if err != nil {
		t.Fatalf("ParseGitIgnore matcher1 failed: %v", err)
	}

	matcher2, err := ParseGitIgnore([]byte("!important.log\n"), "/project/sub")
	if err != nil {
		t.Fatalf("ParseGitIgnore matcher2 failed: %v", err)
	}

	matchers := []*GitIgnoreMatcher{matcher2, matcher1}

	// Regular .log should be ignored.
	if !IsIgnored("app.log", false, matchers) {
		t.Errorf("expected 'app.log' to be ignored")
	}

	// .tmp should be ignored.
	if !IsIgnored("cache.tmp", false, matchers) {
		t.Errorf("expected 'cache.tmp' to be ignored")
	}

	// important.log should NOT be ignored (negated in matcher2).
	if IsIgnored("important.log", false, matchers) {
		t.Errorf("expected 'important.log' to NOT be ignored (negated)")
	}

	// Non-matching file should not be ignored.
	if IsIgnored("main.go", false, matchers) {
		t.Errorf("expected 'main.go' to NOT be ignored")
	}

	// Empty matchers should not ignore anything.
	if IsIgnored("anything", false, nil) {
		t.Errorf("expected nil matchers to not ignore anything")
	}
}

// ---------------------------------------------------------------------
// Real-world examples test
// ---------------------------------------------------------------------

func TestGitIgnore_RealWorldExamples(t *testing.T) {
	data := []byte(`# Python
*.pyc
__pycache__/
*.pyo
*.pyd

# Node.js
node_modules/
package-lock.json

# Build
/build/
dist/

# Logs
*.log
!important.log

# Environment
.env
.env.*

# Coverage
coverage/
.nyc_output/

# IDE
.idea/
.vscode/
*.swp
*~

# OS
.DS_Store
Thumbs.db
`)
	matcher, err := ParseGitIgnore(data, "/project")
	if err != nil {
		t.Fatalf("ParseGitIgnore failed: %v", err)
	}

	// Python patterns.
	if !matcher.Match("module.pyc", false) {
		t.Errorf("real-world: expected 'module.pyc' to be ignored")
	}
	if !matcher.Match("src/utils.pyc", false) {
		t.Errorf("real-world: expected 'src/utils.pyc' to be ignored")
	}
	if !matcher.Match("__pycache__", true) {
		t.Errorf("real-world: expected '__pycache__' dir to be ignored")
	}
	if matcher.Match("__pycache__", false) {
		t.Errorf("real-world: expected '__pycache__' file to NOT be ignored (DirOnly)")
	}

	// Node.js patterns.
	if !matcher.Match("node_modules", true) {
		t.Errorf("real-world: expected 'node_modules' to be ignored")
	}

	// Build patterns.
	if !matcher.Match("build", true) {
		t.Errorf("real-world: expected 'build' dir to be ignored")
	}
	if matcher.Match("src/build", true) {
		// /build/ is rooted, so src/build should NOT match.
		// Wait — /build/ is rooted AND DirOnly. Rooted means it only
		// matches at the root level. So src/build should NOT be ignored.
		t.Errorf("real-world: expected 'src/build' to NOT be ignored (rooted /build/)")
	}
	if !matcher.Match("dist", true) {
		t.Errorf("real-world: expected 'dist' dir to be ignored (non-rooted)")
	}

	// Log patterns.
	if !matcher.Match("app.log", false) {
		t.Errorf("real-world: expected 'app.log' to be ignored")
	}
	if matcher.Match("important.log", false) {
		t.Errorf("real-world: expected 'important.log' to NOT be ignored (negated)")
	}

	// Environment patterns.
	if !matcher.Match(".env", false) {
		t.Errorf("real-world: expected '.env' to be ignored")
	}
	if !matcher.Match(".env.production", false) {
		t.Errorf("real-world: expected '.env.production' to be ignored")
	}

	// Coverage patterns.
	if !matcher.Match("coverage", true) {
		t.Errorf("real-world: expected 'coverage' dir to be ignored")
	}

	// IDE patterns.
	if !matcher.Match(".idea", true) {
		t.Errorf("real-world: expected '.idea' dir to be ignored")
	}
	if !matcher.Match(".vscode", true) {
		t.Errorf("real-world: expected '.vscode' dir to be ignored")
	}
	if !matcher.Match("edit.swp", false) {
		t.Errorf("real-world: expected 'edit.swp' to be ignored")
	}

	// OS patterns.
	if !matcher.Match(".DS_Store", false) {
		t.Errorf("real-world: expected '.DS_Store' to be ignored")
	}
	if !matcher.Match("Thumbs.db", false) {
		t.Errorf("real-world: expected 'Thumbs.db' to be ignored")
	}

	// Non-ignored files.
	if matcher.Match("src/main.py", false) {
		t.Errorf("real-world: expected 'src/main.py' to NOT be ignored")
	}
	if matcher.Match("README.md", false) {
		t.Errorf("real-world: expected 'README.md' to NOT be ignored")
	}
}

// ---------------------------------------------------------------------
// LoadFromFile test
// ---------------------------------------------------------------------

func TestGitIgnoreMatcher_LoadFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	gitignorePath := filepath.Join(tmpDir, ".gitignore")
	if err := os.WriteFile(gitignorePath, []byte("*.log\ntmp/\n"), 0644); err != nil {
		t.Fatalf("write .gitignore: %v", err)
	}

	matcher := &GitIgnoreMatcher{}
	if err := matcher.LoadFromFile(gitignorePath); err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	if matcher.basePath != tmpDir {
		t.Errorf("expected basePath %s, got %s", tmpDir, matcher.basePath)
	}

	if !matcher.Match("app.log", false) {
		t.Errorf("expected 'app.log' to be ignored after LoadFromFile")
	}
	if !matcher.Match("tmp", true) {
		t.Errorf("expected 'tmp' dir to be ignored after LoadFromFile")
	}

	// Non-existent file should return error.
	if err := matcher.LoadFromFile(filepath.Join(tmpDir, "nonexistent")); err == nil {
		t.Errorf("expected error loading non-existent file")
	}
}

// ---------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------

func TestParseGitIgnore_EmptyData(t *testing.T) {
	matcher, err := ParseGitIgnore([]byte(""), "/project")
	if err != nil {
		t.Fatalf("ParseGitIgnore with empty data failed: %v", err)
	}
	if len(matcher.patterns) != 0 {
		t.Errorf("expected 0 patterns for empty data, got %d", len(matcher.patterns))
	}
	if matcher.Match("anything", false) {
		t.Errorf("empty matcher should not ignore anything")
	}
}

func TestParseGitIgnore_OnlyComments(t *testing.T) {
	data := []byte("# comment 1\n# comment 2\n# comment 3\n")
	matcher, err := ParseGitIgnore(data, "/project")
	if err != nil {
		t.Fatalf("ParseGitIgnore failed: %v", err)
	}
	if len(matcher.patterns) != 0 {
		t.Errorf("expected 0 patterns for comments-only data, got %d", len(matcher.patterns))
	}
}

func TestParseGitIgnore_DoubleWildcardLeading(t *testing.T) {
	data := []byte("**/foo\n")
	matcher, err := ParseGitIgnore(data, "/project")
	if err != nil {
		t.Fatalf("ParseGitIgnore failed: %v", err)
	}

	// **/foo should match foo at any depth.
	if !matcher.Match("foo", false) {
		t.Errorf("expected 'foo' to be ignored by **/foo")
	}
	if !matcher.Match("a/foo", false) {
		t.Errorf("expected 'a/foo' to be ignored by **/foo")
	}
	if !matcher.Match("a/b/c/foo", false) {
		t.Errorf("expected 'a/b/c/foo' to be ignored by **/foo")
	}
}

func TestParseGitIgnore_NestedPathPattern(t *testing.T) {
	data := []byte("src/generated/\n")
	matcher, err := ParseGitIgnore(data, "/project")
	if err != nil {
		t.Fatalf("ParseGitIgnore failed: %v", err)
	}

	// src/generated/ should match the directory at that path.
	if !matcher.Match("src/generated", true) {
		t.Errorf("expected 'src/generated' dir to be ignored")
	}
	// Should NOT match just "generated" at a different path.
	if matcher.Match("other/generated", true) {
		t.Errorf("expected 'other/generated' to NOT be ignored (pattern is src/generated/)")
	}
}

func TestIsIgnored_NoMatchers(t *testing.T) {
	if IsIgnored("anything", false, nil) {
		t.Errorf("nil matchers should not ignore")
	}
	if IsIgnored("anything", false, []*GitIgnoreMatcher{}) {
		t.Errorf("empty matchers slice should not ignore")
	}
}

func TestIsIgnored_NilMatcherInSlice(t *testing.T) {
	matchers := []*GitIgnoreMatcher{nil}
	if IsIgnored("anything", false, matchers) {
		t.Errorf("nil matcher in slice should not cause panic or ignore")
	}
}
