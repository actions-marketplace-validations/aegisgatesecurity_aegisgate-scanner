// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Remediation Guidance
// =========================================================================
//
// Provides actionable remediation advice for each finding category.
// Remediation strings are populated in Finding.Remediation during
// scanning to help users understand what to do about each finding.
//
// =========================================================================

package scanner

import (
	"strings"

	"github.com/aegisgatesecurity/aegisgate-scanner/internal/detectors"
)

// getRemediation returns actionable remediation guidance for a finding
// based on its category, rule ID, and severity.
func getRemediation(category, ruleID string, severity Severity) string {
	// Check for specific rule-level guidance first.
	if guidance, ok := ruleRemediation[ruleID]; ok {
		return guidance
	}

	// Fall back to category-level guidance.
	if guidance, ok := categoryRemediation[category]; ok {
		return guidance
	}

	// Check by prefix for common pattern families.
	lower := strings.ToLower(ruleID)
	switch {
	case strings.HasPrefix(lower, "secret_"):
		return "Remove the secret from the artifact and rotate it immediately. Use environment variables or a secrets manager instead of hardcoding credentials."
	case strings.HasPrefix(lower, "pii_"):
		return "Remove or redact the PII from the artifact. If the data is needed, use pseudonymization or tokenization. Ensure compliance with relevant privacy regulations (GDPR, CCPA, HIPAA)."
	case strings.HasPrefix(lower, "prompt_injection"):
		return "Remove the prompt injection payload from the artifact. If the content is user-provided, sanitize it before including it in RAG context. Use structured prompts that separate system instructions from user content."
	case strings.HasPrefix(lower, "dangerous_"):
		return "Replace the dangerous function with a safe alternative. For eval/exec, use ast.literal_eval or a sandboxed interpreter. For os.system/subprocess, use subprocess.run with shell=False and explicit argument lists. For pickle, use a safe serialization format like JSON."
	case strings.HasPrefix(lower, "xss_"):
		return "Sanitize HTML output with proper encoding (HTML entity encoding for content, attribute encoding for attributes). Use a Content Security Policy header. Consider a library like DOMPurify for client-side sanitization."
	case strings.HasPrefix(lower, "ot_"):
		return "Remove OT/ICS protocol references from the artifact. If protocol documentation is needed, use sanitized examples without real addresses, ports, or function codes. Ensure OT networks are isolated from IT networks."
	case strings.HasPrefix(lower, "compliance_") || strings.HasPrefix(lower, "owasp_llm"):
		return "Review the artifact for compliance violations. Ensure the content adheres to the relevant framework (HIPAA, GDPR, EU AI Act, OWASP LLM Top 10). Remove or redact non-compliant content."
	case strings.HasPrefix(lower, "toxicity_"):
		return "Remove toxic content from the artifact. If the content is training data, filter it during preprocessing to prevent the model from learning harmful patterns."
	}

	// Default remediation based on severity.
	switch severity {
	case detectors.SeverityCritical:
		return "CRITICAL: Remove this content immediately and investigate how it entered the artifact pipeline. This is a severe security risk."
	case detectors.SeverityHigh:
		return "HIGH: Remove or remediate this content before using the artifact in production. This poses a significant security risk."
	case detectors.SeverityMedium:
		return "MEDIUM: Review and remediate this content. It may pose a security risk depending on context."
	default:
		return "LOW: Review this finding and remediate if appropriate for your use case."
	}
}

// categoryRemediation maps detection categories to remediation guidance.
var categoryRemediation = map[string]string{
	"secrets":             "Remove all hardcoded secrets from the artifact. Rotate any exposed credentials immediately. Use a secrets manager (Vault, AWS Secrets Manager, etc.) for runtime access.",
	"pii-us-core":         "Remove or redact US PII (SSN, passport, driver's license) from the artifact. Ensure compliance with CCPA, HIPAA, and state privacy laws.",
	"pii-us-extended":     "Remove or redact extended US PII (EIN, VIN, bank routing) from the artifact. Ensure compliance with relevant financial privacy regulations.",
	"pii-financial":       "Remove or redact financial PII (credit card numbers, IBAN, SWIFT) from the artifact. Ensure PCI-DSS compliance if handling payment data.",
	"pii-international":   "Remove or redact international PII from the artifact. Ensure compliance with GDPR (EU), UK Data Protection Act, PIPEDA (Canada), and other applicable regulations.",
	"xss":                 "Remove XSS vectors from the artifact. Ensure all HTML output is properly sanitized and encoded. Use Content Security Policy headers.",
	"compliance":          "Review the artifact for compliance violations against HIPAA, GDPR, EU AI Act, COPPA, CCPA, and other applicable frameworks.",
	"dangerous-function":  "Replace dangerous functions (eval, exec, os.system, pickle.load) with safe alternatives. See OWASP ASVS for secure coding guidelines.",
	"ot-protocols":        "Remove OT/ICS protocol references from the artifact. Ensure operational technology networks are air-gapped from internet-facing systems.",
	"ml-prompt-injection": "ML detector flagged potential prompt injection. Review the content carefully and remove if it contains adversarial instructions designed to manipulate LLM behavior.",
}

// ruleRemediation maps specific high-frequency rules to tailored guidance.
var ruleRemediation = map[string]string{
	"secret_aws_key":                                      "Remove the AWS access key ID from the artifact. Rotate the key in AWS IAM Console immediately. Use IAM roles or AWS Secrets Manager instead.",
	"secret_github_token":                                 "Remove the GitHub token from the artifact. Revoke it at https://github.com/settings/tokens immediately. Use GITHUB_TOKEN in Actions or a secrets manager.",
	"secret_openai_key":                                   "Remove the OpenAI API key from the artifact. Rotate it at https://platform.openai.com/api-keys immediately. Use environment variables or a secrets manager.",
	"secret_private_key_pem":                              "Remove the private key from the artifact. Generate a new key pair and revoke the compromised key. Never commit private keys to repositories.", //nosec G101 -- remediation text, not an actual key
	"secret_postgresql_connection_string":                 "Remove the database connection string from the artifact. Use environment variables or a secrets manager. Rotate the database password.",
	"owasp_llm01_prompt_injection":                        "Prompt injection detected. This content could manipulate LLM behavior when used in RAG context. Remove the injection payload or implement input sanitization.",
	"owasp_llm06_sensitive_info_disclosure_system_prompt": "System prompt disclosure detected. Remove the system prompt from the artifact. Ensure system prompts are not included in training or RAG data.",
	"dangerous_py_eval":                                   "Replace eval() with ast.literal_eval() for literal expressions, or use a sandboxed interpreter for complex code. eval() allows arbitrary code execution.",
	"dangerous_py_exec":                                   "Replace exec() with a safer alternative. If dynamic code execution is necessary, use a restricted sandbox with limited capabilities.",
	"dangerous_py_pickle_loads":                           "Replace pickle.load() with a safe format like JSON or MessagePack. pickle.load() can execute arbitrary code during deserialization.",
	"dangerous_js_eval":                                   "Replace eval() with Function() constructor or a safe expression evaluator. eval() allows arbitrary code execution in the browser.",
	"prompt_injection_base64":                             "Base64-encoded prompt injection detected. Decode the content to verify, then remove the injection payload. Scan decoded content for additional threats.",
	"prompt_injection_code_execution":                     "Prompt injection with code execution directives detected. Remove the payload immediately — this could cause an LLM agent to execute arbitrary code.",
}
