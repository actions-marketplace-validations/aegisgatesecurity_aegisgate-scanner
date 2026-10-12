// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — .gitignore Pattern Parser & Matcher
// =========================================================================
//
// A minimal .gitignore parser with no external dependencies.
//
// Supported pattern syntax:
//   - Comment lines starting with #
//   - Empty lines (ignored)
//   - Negation patterns starting with ! (un-ignore)
//   - Directory-only patterns ending with /
//   - Root-anchored patterns starting with / (relative to .gitignore location)
//   - Wildcard * (matches anything except /)
//   - Double wildcard ** (matches anything including /)
//   - Character classes [abc] and [!abc]
//   - Question mark ? (matches any single character except /)
//
// =========================================================================

package artifacts

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------

// GitIgnorePattern represents a single parsed .gitignore pattern.
type GitIgnorePattern struct {
	// Pattern is the original pattern text.
	Pattern string

	// Negated is true if the pattern starts with !.
	Negated bool

	// DirOnly is true if the pattern ends with /.
	DirOnly bool

	// Rooted is true if the pattern starts with /.
	Rooted bool

	// Regex is the compiled regex for matching.
	Regex *regexp.Regexp
}

// GitIgnoreMatcher holds a set of patterns from a single .gitignore file.
type GitIgnoreMatcher struct {
	patterns []GitIgnorePattern
	basePath string // directory containing the .gitignore file
}

// ---------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------

// ParseGitIgnore parses .gitignore content and returns a matcher.
// basePath is the directory containing the .gitignore file, used for
// resolving root-anchored patterns.
func ParseGitIgnore(data []byte, basePath string) (*GitIgnoreMatcher, error) {
	matcher := &GitIgnoreMatcher{
		basePath: filepath.Clean(basePath),
	}

	lines := strings.Split(string(data), "\n")
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")

		// Trim trailing whitespace but preserve leading whitespace per
		// gitignore semantics (leading spaces are significant except
		// that a single leading space before ! can be escaped). We keep
		// it simple: trim leading/trailing spaces.
		line = strings.TrimSpace(line)

		// Skip empty lines and comments.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		pattern, err := compilePattern(line)
		if err != nil {
			return nil, fmt.Errorf("compile gitignore pattern %q: %w", line, err)
		}

		matcher.patterns = append(matcher.patterns, pattern)
	}

	return matcher, nil
}

// compilePattern converts a single .gitignore pattern line into a
// GitIgnorePattern with a compiled regex.
func compilePattern(line string) (GitIgnorePattern, error) {
	p := GitIgnorePattern{Pattern: line}

	// Step 1: Strip leading ! (set Negated).
	if strings.HasPrefix(line, "!") {
		p.Negated = true
		line = line[1:]
	}

	// Step 2: Strip trailing / (set DirOnly).
	if strings.HasSuffix(line, "/") {
		p.DirOnly = true
		line = strings.TrimSuffix(line, "/")
	}

	// Step 3: Strip leading / (set Rooted).
	if strings.HasPrefix(line, "/") {
		p.Rooted = true
		line = line[1:]
	}

	// Step 4: Convert glob to regex.
	regexStr := globToRegex(line)

	// Step 5 & 6: Apply anchoring.
	if p.Rooted {
		// Rooted: match from the beginning of the path (relative to base).
		regexStr = "^" + regexStr + "$"
	} else {
		// Non-rooted: match at any path segment boundary.
		// The pattern can match any path component or a suffix of the path.
		regexStr = "(^|/)" + regexStr + "$"
	}

	re, err := regexp.Compile(regexStr)
	if err != nil {
		return p, fmt.Errorf("compile regex %q: %w", regexStr, err)
	}
	p.Regex = re

	return p, nil
}

// globToRegex converts a gitignore glob pattern to a regex string.
//
// Conversions:
//   - **  → .* (matches anything including /)
//   - *   → [^/]* (matches anything except /)
//   - ?   → [^/] (matches single char except /)
//   - [abc]  → [abc] (character class, pass through)
//   - [!abc] → [^abc] (negated character class)
//   - . and other regex metacharacters → escaped
func globToRegex(glob string) string {
	var sb strings.Builder
	sb.Grow(len(glob) * 2)

	i := 0
	for i < len(glob) {
		ch := glob[i]

		switch ch {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				// Double wildcard ** matches anything including /.
				sb.WriteString(".*")
				i += 2
				// If ** is followed by /, consume the / too since **/ means
				// "match at any directory level" — the .* already covers it.
				if i < len(glob) && glob[i] == '/' {
					// **/ — match zero or more path segments.
					// We emit .*/? so that **/foo matches foo, a/foo, a/b/foo.
					sb.WriteString("/?")
					i++
				}
			} else {
				// Single wildcard * matches anything except /.
				sb.WriteString("[^/]*")
				i++
			}

		case '?':
			sb.WriteString("[^/]")
			i++

		case '[':
			// Character class.
			end := strings.IndexByte(glob[i+1:], ']')
			if end == -1 {
				// No closing bracket — treat [ as literal.
				sb.WriteString("\\[")
				i++
				break
			}
			// Extract the character class content.
			classContent := glob[i+1 : i+1+end]
			// Handle negation: [!...] → [^...]
			if strings.HasPrefix(classContent, "!") {
				classContent = "^" + classContent[1:]
			}
			sb.WriteString("[")
			sb.WriteString(classContent)
			sb.WriteString("]")
			i += end + 2 // skip [content]

		default:
			// Escape regex metacharacters.
			if isRegexMeta(ch) {
				sb.WriteByte('\\')
			}
			sb.WriteByte(ch)
			i++
		}
	}

	return sb.String()
}

// isRegexMeta returns true if the byte is a regex metacharacter that
// needs escaping when used as a literal.
func isRegexMeta(ch byte) bool {
	switch ch {
	case '.', '+', '(', ')', '{', '}', '^', '$', '|', '\\':
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------

// Match checks if a path is ignored by this matcher's patterns.
// path should be relative to the same root as basePath. isDir indicates
// whether the path is a directory.
func (m *GitIgnoreMatcher) Match(path string, isDir bool) bool {
	ignored, _ := m.matchDetail(path, isDir)
	return ignored
}

// matchDetail checks if a path is ignored and whether any pattern matched.
// Returns (ignored, matched). If no pattern matched, returns (false, false).
func (m *GitIgnoreMatcher) matchDetail(path string, isDir bool) (bool, bool) {
	if m == nil || len(m.patterns) == 0 {
		return false, false
	}

	// Normalize path separators.
	normalized := filepath.ToSlash(path)

	// If the path is relative to a different base, try to make it
	// relative to this matcher's basePath.
	rel := normalized
	if m.basePath != "" && m.basePath != "." {
		// Try to strip the basePath prefix if present.
		baseSlash := filepath.ToSlash(m.basePath)
		if strings.HasPrefix(normalized, baseSlash+"/") {
			rel = strings.TrimPrefix(normalized, baseSlash+"/")
		}
	}

	ignored := false
	matched := false
	for _, p := range m.patterns {
		// DirOnly patterns only match directories.
		if p.DirOnly && !isDir {
			continue
		}

		if p.Regex.MatchString(rel) {
			matched = true
			if p.Negated {
				// Negation un-ignores.
				ignored = false
			} else {
				ignored = true
			}
		}
	}

	return ignored, matched
}

// LoadFromFile loads patterns from a .gitignore file.
func (m *GitIgnoreMatcher) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read gitignore file: %w", err)
	}

	// Set basePath to the directory containing the file.
	m.basePath = filepath.Dir(path)

	lines := strings.Split(string(data), "\n")
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		pattern, err := compilePattern(line)
		if err != nil {
			return fmt.Errorf("compile gitignore pattern %q: %w", line, err)
		}

		m.patterns = append(m.patterns, pattern)
	}

	return nil
}

// ---------------------------------------------------------------------
// Hierarchy
// ---------------------------------------------------------------------

// LoadGitIgnoreHierarchy walks up from root to find all .gitignore files
// in the directory and its parent directories. The returned matchers are
// ordered from the root directory first, then progressively upward.
func LoadGitIgnoreHierarchy(root string) ([]*GitIgnoreMatcher, error) {
	var matchers []*GitIgnoreMatcher

	// Resolve to absolute path.
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve root path: %w", err)
	}

	// Collect directories from root upward to filesystem root.
	var dirs []string
	dir := absRoot
	for {
		dirs = append(dirs, dir)
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	// Process from root upward (dirs is already root-first).
	for _, d := range dirs {
		gitignorePath := filepath.Join(d, ".gitignore")
		info, err := os.Stat(gitignorePath)
		if err != nil || info.IsDir() {
			continue
		}

		data, err := os.ReadFile(gitignorePath)
		if err != nil {
			continue // silently skip unreadable files
		}

		matcher, err := ParseGitIgnore(data, d)
		if err != nil {
			continue // silently skip unparseable files
		}

		matchers = append(matchers, matcher)
	}

	return matchers, nil
}

// IsIgnored checks a path against all matchers in the hierarchy.
// The matchers should be ordered from the most specific (closest to the
// file) to the most general (filesystem root). The first matcher that
// has a matching pattern determines the result — closer .gitignore
// files take precedence over parent .gitignore files.
func IsIgnored(path string, isDir bool, matchers []*GitIgnoreMatcher) bool {
	for _, m := range matchers {
		if m == nil {
			continue
		}
		ignored, matched := m.matchDetail(path, isDir)
		if matched {
			return ignored
		}
	}
	return false
}
