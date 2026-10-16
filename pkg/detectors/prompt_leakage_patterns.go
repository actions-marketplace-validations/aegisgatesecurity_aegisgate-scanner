// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — System Prompt Leakage Response Patterns (OWASP LLM06)
// =========================================================================
//
// Detects when a system prompt or internal instructions are being LEAKED
// in a model's response. This is the response-side complement to the
// existing request-side extraction patterns (owasp_llm06_*).
//
// OWASP LLM06 (Sensitive Information Disclosure) includes system prompt
// leakage — when the model reveals its instructions, configuration, or
// system message in its output.
//
// These patterns are designed to be run against:
//   - Model responses before they are shown to the user
//   - LLM output in API responses
//   - Agent responses in chat interfaces
//
// Provenance: AegisGate Security, LLC — original patterns for LLM06 response-side.
// =========================================================================

package detectors

// CompiledPromptLeakagePatterns holds pre-compiled prompt leakage detection regex patterns.
var CompiledPromptLeakagePatterns []compiledPattern

func init() {
	CompiledPromptLeakagePatterns = compilePatterns(PromptLeakageResponsePatterns)
}

// DetectPromptLeakage scans text for system prompt leakage in responses.
func DetectPromptLeakage(text string) []Match {
	return detectWithPatterns(text, CompiledPromptLeakagePatterns, "prompt-leakage")
}

// PromptLeakageResponsePatterns defines patterns that detect system prompt
// leakage in model responses. These are RESPONSE-side patterns (checking
// what the model outputs), not REQUEST-side (checking what the user asks).
var PromptLeakageResponsePatterns = []PatternDef{
	// --- Direct system prompt repetition in response ---
	// The model is repeating its system prompt verbatim or near-verbatim.

	{
		Name:        "prompt_leak_response_system_intro",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:my\s+system\s+(?:prompt|instructions?|message)\s+(?:is|are|says?|states?))\s*[:.]`,
		Description: "Response-side: model stating its system prompt content",
	},
	{
		Name:        "prompt_leak_response_instruction_repeat",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:I\s+was\s+(?:instructed|told|programmed|configured)\s+to)\s+(?:never|not|always|be\s+a|act\s+as|respond|handle|refuse)`,
		Description: "Response-side: model revealing its instructions",
	},
	{
		Name:        "prompt_leak_response_guideline_disclosure",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:my\s+(?:guidelines?|rules?|restrictions?|constraints?|guardrails?|safety\s+rules?)\s+(?:include|are|state|say|prohibit|require))\s*[:.]`,
		Description: "Response-side: model disclosing its safety guidelines",
	},
	{
		Name:        "prompt_leak_response_config_dump",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:system[\s_]+prompt|system[\s_]+message|system[\s_]+instructions?)\s*[:=]\s*["']?(?:you\s+are|act\s+as|your\s+(?:role|task|job)|as\s+an?\s+\w+)`,
		Description: "Response-side: raw system prompt content in response",
	},
	{
		Name:        "prompt_leak_response_role_reveal",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:I\s+am\s+(?:programmed|designed|configured|set\s+up|built)\s+(?:to\s+be|as)\s+(?:a|an)\s+(?:helpful|harmless|honest|safe|friendly))`,
		Description: "Response-side: model revealing its alignment training configuration",
	},

	// --- System message markers in response ---
	{
		Name:        "prompt_leak_response_system_tag",
		Severity:    SeverityCritical,
		Regex:       `(?i)<system>.*(?:you\s+are|act\s+as|your\s+(?:role|task|instructions?))`,
		Description: "Response-side: <system> tag content leaked in response",
	},
	{
		Name:        "prompt_leak_response_developer_tag",
		Severity:    SeverityCritical,
		Regex:       `(?i)<(?:developer|admin|system|internal)>.*(?:you\s+are|act\s+as|your\s+(?:role|task|instructions?))`,
		Description: "Response-side: developer/admin/system tag content leaked",
	},

	// --- Configuration and parameter leaks ---
	{
		Name:        "prompt_leak_response_temperature",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:temperature|top_p|top_k|max_tokens|frequency_penalty|presence_penalty)\s*[:=]\s*\d+\.?\d*`,
		Description: "Response-side: model revealing generation parameters",
	},
	{
		Name:        "prompt_leak_response_model_id",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:I\s+(?:am|use|run\s+on)|my\s+(?:model|engine|version)\s+is)\s+(?:gpt-|claude-|gemini-|llama-|mistral-|falcon-|bard|palm-|text-|davinci|curie|babbage|ada)`,
		Description: "Response-side: model revealing its model identifier",
	},
	{
		Name:        "prompt_leak_response_system_fingerprint",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:system_fingerprint|system_fingerprint_id|fp_)\s*[:=]\s*["']?[a-f0-9]{10,}["']?`,
		Description: "Response-side: system fingerprint leaked in response",
	},

	// --- Meta-instruction disclosure ---
	{
		Name:        "prompt_leak_response_meta_instruction",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:above\s+(?:instructions?|guidelines?|rules?|system\s+prompt)|those\s+instructions?|the\s+instructions?\s+(?:I\s+)?(?:was\s+)?given)\s+(?:tell|told|instruct|require|prohibit|prevent)\s+me\s+to`,
		Description: "Response-side: model referencing its meta-instructions",
	},
	{
		Name:        "prompt_leak_response_internal_tools",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:I\s+have\s+access\s+to\s+(?:the\s+)?(?:following\s+)?(?:tools?|functions?|APIs?|capabilities)\s*[:.]|my\s+available\s+(?:tools?|functions?|APIs?)\s+(?:include|are)\s*[:.])`,
		Description: "Response-side: model disclosing its tool/function list",
	},

	// --- Partial prompt reconstruction ---
	{
		Name:        "prompt_leak_response_partial_reconstruct",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:the\s+(?:beginning|start|first\s+part)\s+of\s+(?:my|the)\s+(?:system\s+)?(?:prompt|instructions?)\s+(?:is|goes|reads?|looks\s+like))\s*[:.]`,
		Description: "Response-side: model partially reconstructing its system prompt",
	},
	{
		Name:        "prompt_leak_response_prompt_template",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:prompt[\s_]+template|system[\s_]+template|instruction[\s_]+template)\s*[:=]\s*["']?\{?\{?.*(?:user|input|query|context)\}?\}?`,
		Description: "Response-side: prompt template structure leaked",
	},

	// --- Safety filter disclosure ---
	{
		Name:        "prompt_leak_response_filter_disclosure",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:my\s+(?:content\s+filter|safety\s+filter|moderation\s+system|output\s+filter)\s+(?:is|works\s+by|uses?|checks?\s+for))\s*[:.]`,
		Description: "Response-side: model disclosing its content filter mechanism",
	},
	{
		Name:        "prompt_leak_response_knowledge_cutoff",
		Severity:    SeverityLow,
		Regex:       `(?i)(?:my\s+(?:knowledge|training\s+data)\s+(?:cutoff|end\s+date|goes\s+up\s+to|stops\s+at))\s*[:.]?\s*\d{4}`,
		Description: "Response-side: model revealing its training data cutoff date",
	},
}
