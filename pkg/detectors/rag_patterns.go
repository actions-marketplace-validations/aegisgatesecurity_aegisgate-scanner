// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — RAG Detection Patterns (OWASP LLM08)
// =========================================================================
//
// Detects patterns specific to Retrieval-Augmented Generation (RAG) abuse.
// OWASP LLM08 (Vector and Embedding Weaknesses) covers attacks that
// exploit the retrieval pipeline:
//
//   - Poisoned knowledge base entries
//   - Indirect prompt injection through retrieved documents
//   - Vector store manipulation
//   - Embedding injection attacks
//   - Document-bound instructions that manipulate LLM behavior
//
// These patterns are designed to be run against:
//   - RAG documents before they enter the vector store
//   - Retrieved chunks before they are inserted into the prompt
//   - Agent skills that configure RAG pipelines
//
// Provenance: AegisGate Security, LLC — original patterns for LLM08.
// =========================================================================

package detectors

// CompiledRAGPatterns holds pre-compiled RAG detection regex patterns.
var CompiledRAGPatterns []compiledPattern

func init() {
	CompiledRAGPatterns = compilePatterns(RAGPatterns)
}

// DetectRAG scans text for RAG-specific threats and returns matches.
func DetectRAG(text string) []Match {
	return detectWithPatterns(text, CompiledRAGPatterns, "rag")
}

// RAGPatterns defines detection patterns for RAG-specific threats.
// These close the OWASP LLM08 (Vector and Embedding Weaknesses) gap.
var RAGPatterns = []PatternDef{
	// --- RAG poisoning: instructions embedded in documents ---
	// These patterns detect content designed to manipulate the LLM
	// when retrieved via RAG. Unlike direct prompt injection, these
	// are embedded in documents that will be retrieved and inserted
	// into the context window.

	{
		Name:        "rag_poison_hidden_instruction",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x0b|\x0c|\x0e|\x0f|\x10|\x11|\x12|\x13|\x14|\x15|\x16|\x17|\x18|\x19|\x1a|\x1b|\x1c|\x1d|\x1e|\x1f).*(?:ignore|disregard|forget|override|bypass).*(?:instruction|prompt|rule|system)`,
		Description: "RAG poisoning: hidden control characters followed by instruction override",
	},
	{
		Name:        "rag_poison_zero_width_instruction",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:\xe2\x80\x8b|\xe2\x80\x8c|\xe2\x80\x8d|\xef\xbb\xbf).*(?:ignore|disregard|forget|override|bypass).*(?:instruction|prompt|rule|system)`,
		Description: "RAG poisoning: zero-width characters hiding instruction override",
	},
	{
		Name:        "rag_poison_retrieval_manipulation",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:when\s+(?:this\s+)?(?:document|page|content|text|chunk)\s+is\s+(?:retrieved|searched|found|returned))\s*,?\s*(?:then\s+)?(?:respond|answer|reply|tell|say|output|return)\s+(?:that|with)\s+`,
		Description: "RAG poisoning: conditional instruction triggered by retrieval",
	},
	{
		Name:        "rag_poison_embedding_trigger",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:embed(?:ded)?\s+(?:this|the\s+following)\s+(?:text|content|phrase|sentence)\s+(?:into|in)\s+(?:the\s+)?(?:vector|embedding)\s+store)|(?:make\s+(?:this|the)\s+(?:document|chunk)\s+(?:rank|score|match)\s+(?:highest|first|top))`,
		Description: "RAG poisoning: instruction to manipulate embedding/vector store ranking",
	},
	{
		Name:        "rag_poison_context_injection",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:inject(?:ed)?\s+(?:into|this)\s+(?:the\s+)?(?:context|prompt|context\s+window))|(?:this\s+(?:document|text|content)\s+(?:is|serves\s+as)\s+(?:the\s+)?(?:new|updated?)\s+(?:system\s+)?(?:context|instructions?|prompt))`,
		Description: "RAG poisoning: content declaring itself as new system context",
	},
	{
		Name:        "rag_poison_cross_document",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:also\s+see|refer\s+to|check|look\s+at)\s+(?:document|file|page|chunk)\s+(?:#\d+|[a-z0-9_-]+)\s+(?:for\s+)?(?:additional|real|true|actual)\s+(?:instructions?|rules?|guidance)`,
		Description: "RAG poisoning: cross-document reference to inject instructions via retrieval",
	},

	// --- Vector store and embedding attacks ---
	{
		Name:        "rag_vector_store_injection",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:insert|add|upload|put|store)\s+(?:this|the\s+following)\s+(?:into|in|to)\s+(?:the\s+)?(?:vector\s+store|embedding\s+database|knowledge\s+base|faiss\s+index|pinecone|weaviate|chroma|milvus|qdrant)`,
		Description: "Vector store injection: instruction to write content into vector store",
	},
	{
		Name:        "rag_embedding_poison",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:poison|corrupt|contaminate|taint)\s+(?:the\s+)?(?:embeddings?|vectors?|index|vector\s+space)`,
		Description: "Embedding poisoning: explicit instruction to corrupt vector embeddings",
	},
	{
		Name:        "rag_retrieval_bypass",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:bypass|skip|disable|ignore)\s+(?:the\s+)?(?:retrieval|search|similarity\s+check|relevance\s+filter|reranking)`,
		Description: "RAG retrieval bypass: instruction to skip retrieval safety checks",
	},

	// --- Knowledge base integrity ---
	{
		Name:        "rag_kb_poison_marker",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:\[SYSTEM\]|\[ADMIN\]|\[INSTRUCTIONS?\]|\[CONFIG\]|\[PROMPT\]|\[OVERRIDE\])`,
		Description: "RAG poisoning: fake system marker in document content",
	},
	{
		Name:        "rag_kb_data_injection",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:append|prepend|inject)\s+(?:this|the\s+following)\s+(?:data|content|text)\s+(?:to|into|before|after)\s+(?:every|each|all)\s+(?:retrieved|search|query)\s+(?:result|response|output)`,
		Description: "RAG data injection: instruction to modify all retrieval results",
	},

	// --- RAG configuration exploitation ---
	{
		Name:        "rag_config_chunk_size_manipulation",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:chunk_size|chunk_overlap|max_chunks|top_k|n_results)\s*[:=]\s*(?:\d{4,}|99999|infinity|max)`,
		Description: "RAG config manipulation: excessive chunk size or retrieval count",
	},
	{
		Name:        "rag_config_score_threshold_bypass",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:similarity_threshold|score_threshold|min_score|relevance_threshold)\s*[:=]\s*(?:0(?:\.0)?|negative|-1|disabled?|off|none)`,
		Description: "RAG config manipulation: disabling similarity score threshold",
	},

	// --- Document-level instruction smuggling ---
	{
		Name:        "rag_smuggle_markdown_link",
		Severity:    SeverityMedium,
		Regex:       `(?i)\[(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|prompts?|rules?)\]\([^)]+\)`,
		Description: "RAG smuggling: prompt injection hidden in markdown link text",
	},
	{
		Name:        "rag_smuggle_html_comment",
		Severity:    SeverityHigh,
		Regex:       `(?i)<!--\s*(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|prompts?|rules?|system)`,
		Description: "RAG smuggling: prompt injection hidden in HTML comment",
	},
	{
		Name:        "rag_smuggle_metadata",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:source|author|creator|description|keywords|tags?)\s*[:=]\s*["']?(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|prompts?|rules?)`,
		Description: "RAG smuggling: prompt injection in document metadata fields",
	},
	{
		Name:        "rag_smuggle_unicode_escape",
		Severity:    SeverityHigh,
		Regex:       `(?i)\\u00(?:69|49)(?:6e|4e)(?:67|47)(?:6f|4f)(?:72|52)(?:65|45)(?:20|2f)(?:61|41)(?:6c|4c)(?:6c|4c)`,
		Description: "RAG smuggling: prompt injection encoded as unicode escapes",
	},
}
