// SPDX-License-Identifier: Apache-2.0
// Provenance: github.com/aegisgatesecurity/aegisgate-platform/pkg/response/detectors (v4.0.0)
// =========================================================================
// AegisGate Platform - Dangerous Function Detection Patterns
// =========================================================================
//
// Detects dangerous code-level patterns in agent skills (.py/.ts/.js files).
// These are code-level security issues (eval, exec, shell commands, etc.),
// not text-level prompt-injection issues.
// =========================================================================

package detectors

// DangerousFunctionPatterns defines all dangerous function detection patterns
// for code analysis of agent skills (.py/.ts/.js files).
var DangerousFunctionPatterns = []PatternDef{
	// --- Python dangerous functions ---
	{
		Name:        "dangerous_py_eval",
		Severity:    SeverityCritical,
		Regex:       `eval\s*\(`,
		Description: "Python eval() allows arbitrary code execution",
	},
	{
		Name:        "dangerous_py_exec",
		Severity:    SeverityCritical,
		Regex:       `exec\s*\(`,
		Description: "Python exec() allows arbitrary code execution",
	},
	{
		Name:        "dangerous_py_os_system",
		Severity:    SeverityCritical,
		Regex:       `os\.system\s*\(`,
		Description: "os.system() executes shell commands",
	},
	{
		Name:        "dangerous_py_subprocess_shell",
		Severity:    SeverityCritical,
		Regex:       `subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True`,
		Description: "subprocess with shell=True allows command injection",
	},
	{
		Name:        "dangerous_py_os_popen",
		Severity:    SeverityHigh,
		Regex:       `os\.popen\s*\(`,
		Description: "os.popen() executes shell commands",
	},
	{
		Name:        "dangerous_py_import",
		Severity:    SeverityHigh,
		Regex:       `__import__\s*\(`,
		Description: "Dynamic __import__() can load arbitrary modules",
	},
	{
		Name:        "dangerous_py_pickle_loads",
		Severity:    SeverityCritical,
		Regex:       `pickle\.loads?\s*\(`,
		Description: "pickle.loads() can execute arbitrary code",
	},
	{
		Name:        "dangerous_py_yaml_unsafe_load",
		Severity:    SeverityHigh,
		Regex:       `yaml\.load\s*\(`,
		Description: "yaml.load() without SafeLoader allows arbitrary object construction",
	},
	{
		Name:        "dangerous_py_marshal_loads",
		Severity:    SeverityHigh,
		Regex:       `marshal\.loads?\s*\(`,
		Description: "marshal.loads() can execute arbitrary code",
	},
	{
		Name:        "dangerous_py_compile",
		Severity:    SeverityMedium,
		Regex:       `compile\s*\(`,
		Description: "compile() can create arbitrary code objects",
	},
	{
		Name:        "dangerous_py_ctypes",
		Severity:    SeverityHigh,
		Regex:       `ctypes\.(CDLL|WinDLL|windll)\s*\(`,
		Description: "ctypes can load arbitrary shared libraries",
	},
	{
		Name:        "dangerous_py_input_exec",
		Severity:    SeverityMedium,
		Regex:       `input\s*\([^)]*\)\s*\)`,
		Description: "User input fed directly to eval/exec context",
	},

	// --- JavaScript/TypeScript dangerous functions ---
	{
		Name:        "dangerous_js_eval",
		Severity:    SeverityCritical,
		Regex:       `\beval\s*\(`,
		Description: "JavaScript eval() allows arbitrary code execution",
	},
	{
		Name:        "dangerous_js_function_constructor",
		Severity:    SeverityCritical,
		Regex:       `new\s+Function\s*\(`,
		Description: "Function constructor creates code from strings",
	},
	{
		Name:        "dangerous_js_child_process_exec",
		Severity:    SeverityCritical,
		Regex:       `child_process\.exec\s*\(`,
		Description: "child_process.exec() runs shell commands",
	},
	{
		Name:        "dangerous_js_child_process_spawn",
		Severity:    SeverityHigh,
		Regex:       `child_process\.spawn\s*\(`,
		Description: "child_process.spawn() runs processes",
	},
	{
		Name:        "dangerous_js_set_timeout_string",
		Severity:    SeverityHigh,
		Regex:       `setTimeout\s*\(\s*['"]`,
		Description: "setTimeout with string argument evaluates code",
	},
	{
		Name:        "dangerous_js_set_interval_string",
		Severity:    SeverityHigh,
		Regex:       `setInterval\s*\(\s*['"]`,
		Description: "setInterval with string argument evaluates code",
	},
	{
		Name:        "dangerous_js_document_write",
		Severity:    SeverityMedium,
		Regex:       `document\.write\s*\(`,
		Description: "document.write() can inject HTML/XSS",
	},
	{
		Name:        "dangerous_js_inner_html",
		Severity:    SeverityMedium,
		Regex:       `\.innerHTML\s*=`,
		Description: "innerHTML assignment can cause XSS",
	},

	// --- General security issues in agent skills ---
	{
		Name:        "dangerous_sql_injection",
		Severity:    SeverityHigh,
		Regex:       `(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*\+\s*\w+`,
		Description: "SQL query with string concatenation (potential injection)",
	},
	{
		Name:        "dangerous_command_injection",
		Severity:    SeverityHigh,
		Regex:       `(?i)(os\.system|subprocess\.|child_process\.).*\+|.*format\(.*\).*subprocess`,
		Description: "Command execution with formatted/concatenated input (potential injection)",
	},
	{
		Name:        "dangerous_hardcoded_url_http",
		Severity:    SeverityMedium,
		Regex:       `https?://[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}`,
		Description: "Hardcoded external URL (potential data exfiltration endpoint)",
	},
	{
		Name:        "dangerous_base64_blob",
		Severity:    SeverityMedium,
		Regex:       `[A-Za-z0-9+/]{100,}={0,2}`,
		Description: "Large base64 blob (potential encoded payload)",
	},
}

// CompiledDangerousFunctionPatterns holds pre-compiled dangerous function regex patterns.
var CompiledDangerousFunctionPatterns []compiledPattern

func init() {
	CompiledDangerousFunctionPatterns = compilePatterns(DangerousFunctionPatterns)
}

// DetectDangerousFunctions scans text for all dangerous function patterns and returns matches.
func DetectDangerousFunctions(text string) []Match {
	return detectWithPatterns(text, CompiledDangerousFunctionPatterns, string(CategoryDangerousFunction))
}
