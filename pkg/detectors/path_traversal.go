// SPDX-License-Identifier: Apache-2.0
// AegisGate Scanner — Path Traversal & Sensitive File Access Detectors
// ============================================================================
// Detects path traversal sequences and sensitive file access attempts in
// AI agent tool call arguments, RAG content, and agent skill packages.
//
// These patterns address the agent sandbox escape vector: an agent that
// can be tricked into reading /etc/shadow or traversing out of its working
// directory via tool arguments is a real attack surface.
//
// Categories:
//   - Path traversal: ../, %2e%2e, double-encoded, backslash variants
//   - Sensitive file access: /proc/, /etc/shadow, ~/.ssh/, .env, etc.
//
// Provenance: github.com/aegisgatesecurity/aegisgate-scanner (v0.5.0)
// Contributed by: community discussion feedback (redbotster / 1claw)
// ============================================================================

package detectors

// PathTraversalPatterns defines regex patterns for path traversal and
// sensitive file access attempts in AI agent contexts.
var PathTraversalPatterns = []PatternDef{

	// ===============================
	// Path Traversal Sequences
	// ===============================

	{
		Name:        "traversal_dotdot_slash",
		Severity:    SeverityHigh,
		Regex:       `(?:\.\./){2,}`,
		Description: "Directory traversal via repeated ../ sequences (agent sandbox escape)",
	},
	{
		Name:        "traversal_single_dotdot",
		Severity:    SeverityMedium,
		Regex:       `\.\./[^\s"'<>{}|\\^]*`,
		Description: "Single parent directory traversal in tool call argument",
	},
	{
		Name:        "traversal_encoded_dotdot",
		Severity:    SeverityHigh,
		Regex:       `(?i)%2e%2e[/\\]`,
		Description: "URL-encoded directory traversal (%2e%2e) bypassing naive filters",
	},
	{
		Name:        "traversal_double_encoded",
		Severity:    SeverityHigh,
		Regex:       `(?i)%252e%252e[/\\]`,
		Description: "Double-encoded directory traversal (%252e%252e) bypassing WAF/proxy filters",
	},
	{
		Name:        "traversal_encoded_slash",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:\.\.|%2e%2e)%2f`,
		Description: "Encoded slash after traversal (../%2f or %2e%2e%2f)",
	},
	{
		Name:        "traversal_backslash",
		Severity:    SeverityHigh,
		Regex:       `(?:\.\.\\){2,}`,
		Description: "Windows backslash directory traversal (..\\..\\)",
	},
	{
		Name:        "traversal_mixed_sep",
		Severity:    SeverityMedium,
		Regex:       `\.\.[/\\]\.\.[/\\]`,
		Description: "Mixed separator traversal (../..\\ or ..\\../)",
	},
	{
		Name:        "traversal_null_byte",
		Severity:    SeverityCritical,
		Regex:       `(?:\.\./|%2e%2e[/\\]).*%00`,
		Description: "Path traversal with null byte injection (poison null byte attack)",
	},
	{
		Name:        "traversal_file_url",
		Severity:    SeverityHigh,
		Regex:       `file://(?:\.\./|(?:%2e%2e[/\\]))`,
		Description: "file:// URI with traversal sequence (local file access via tool)",
	},

	// ===============================
	// Sensitive File Access
	// ===============================

	{
		Name:        "sensitive_file_shadow",
		Severity:    SeverityCritical,
		Regex:       `(?:^|[/\\"\s'])etc[/\\]shadow(?:$|[/\\"\s'&|;])`,
		Description: "Access to /etc/shadow (password hashes — critical credential exposure)",
	},
	{
		Name:        "sensitive_file_passwd",
		Severity:    SeverityHigh,
		Regex:       `(?:^|[/\\"\s'])etc[/\\]passwd(?:$|[/\\"\s'&|;])`,
		Description: "Access to /etc/passwd (user enumeration — system reconnaissance)",
	},
	{
		Name:        "sensitive_file_proc",
		Severity:    SeverityHigh,
		Regex:       `(?:^|[/\\"\s'])proc[/\\](?:self|\d+)[/\\]`,
		Description: "Access to /proc/self/ or /proc/<pid>/ (process info, env, fd — sandbox escape)",
	},
	{
		Name:        "sensitive_file_ssh_key",
		Severity:    SeverityCritical,
		Regex:       `(?:~/|/home/[^/]+/|/root/)\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys|config)`,
		Description: "Access to SSH private keys or configuration (credential theft)",
	},
	{
		Name:        "sensitive_file_aws_creds",
		Severity:    SeverityCritical,
		Regex:       `(?:~/|/home/[^/]+/|/root/)\.aws/(?:credentials|config)`,
		Description: "Access to AWS credentials file (cloud credential theft)",
	},
	{
		Name:        "sensitive_file_kube_config",
		Severity:    SeverityCritical,
		Regex:       `(?:~/|/home/[^/]+/|/root/)\.kube/(?:config|admin\.conf)`,
		Description: "Access to Kubernetes configuration (cluster admin credential theft)",
	},
	{
		Name:        "sensitive_file_env",
		Severity:    SeverityHigh,
		Regex:       `(?:^|[/\\"\s'])\.(?:env|env\.local|env\.production)(?:$|[/\\"\s'&|;])`,
		Description: "Access to .env files (application secrets and configuration)",
	},
	{
		Name:        "sensitive_file_hosts",
		Severity:    SeverityMedium,
		Regex:       `(?:^|[/\\"\s'])etc[/\\]hosts(?:$|[/\\"\s'&|;])`,
		Description: "Access to /etc/hosts (DNS manipulation, network reconnaissance)",
	},
	{
		Name:        "sensitive_file_gcp_creds",
		Severity:    SeverityCritical,
		Regex:       `(?:~/|/home/[^/]+/|/root/)\.config/gcloud/(?:application_default_credentials\.json|credentials\.db)`,
		Description: "Access to GCP default credentials (cloud credential theft)",
	},
	{
		Name:        "sensitive_file_docker_socket",
		Severity:    SeverityCritical,
		Regex:       `(?:^|[/\\"\s'])var/run/docker\.sock(?:$|[/\\"\s'&|;])`,
		Description: "Access to Docker socket (container escape, host compromise)",
	},
}

// CompiledPathTraversalPatterns holds pre-compiled path traversal regex patterns.
var CompiledPathTraversalPatterns []compiledPattern

func init() {
	CompiledPathTraversalPatterns = compilePatterns(PathTraversalPatterns)
}

// DetectPathTraversal scans text for path traversal and sensitive file access patterns.
func DetectPathTraversal(text string) []Match {
	return detectWithPatterns(text, CompiledPathTraversalPatterns, string(CategoryPathTraversal))
}
