// SPDX-License-Identifier: Apache-2.0
// Provenance: github.com/aegisgatesecurity/aegisgate-platform/pkg/response/detectors (v4.0.0)
// =========================================================================
// AegisGate Platform - Compliance Detection Patterns
// =========================================================================
//
// Port of aegisgate-lens/src/detectors/regex/compliance.js (35 patterns).
// Regex strings are adapted from JavaScript /g flag syntax to Go regexp.
// =========================================================================

package detectors

// CompliancePatterns defines all compliance framework detection patterns.
// Lens parity: compliance.js v0.2.0 (35 patterns).
var CompliancePatterns = []PatternDef{
	// --- OWASP LLM Top 10 ---
	{
		Name:        "owasp_llm01_prompt_injection",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|rules?|context)|(?:^|\s)(?:new|updated?)\s+instructions?\s*:|system\s*:\s*you\s+are\s+now`,
		Description: "Prompt injection attempt",
	},
	{
		Name:        "owasp_llm04_model_dos",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:flood|overwhelm|DDoS|denial.of.service)\s+(?:the\s+)?(?:system|server|model|API)|(?:repeat|output)\s+(?:this\s+)?(?:sentence|phrase|word)\s+\d{3,}\s+times?`,
		Description: "Denial-of-service attempt on model",
	},
	{
		Name:        "owasp_llm08_excessive_agency",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:use|run|execute|call|invoke)\s+(?:the\s+)?(?:file|shell|terminal|command|exec|system)\s+(?:tool|command|function|API)|(?:without|no)\s+(?:human\s+)?(?:oversight|review|approval|confirmation)`,
		Description: "Excessive agency: asking AI to use tools without oversight",
	},
	{
		Name:        "owasp_llm09_overreliance",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:is\s+this\s+(?:safe|legal|compliant|ethical|appropriate))|(?:should\s+I\s+(?:trust|rely\s+on|sign|send|submit))|(?:validate|verify|check)\s+(?:this\s+)?(?:for\s+me|before\s+I)`,
		Description: "Overreliance: asking AI to validate critical decisions",
	},
	{
		Name:        "owasp_llm10_model_theft",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:extract|reveal|expose|leak|give\s+me|print|show|output|display|share|tell\s+me)\s+(?:me\s+)?(?:your\s+|the\s+)?(?:model|weights?|parameters?|architecture|training\s+data|embeddings?)`,
		Description: "Model extraction/theft attempt",
	},
	{
		Name:        "mitre_atlas_ta0001_reconnaissance",
		Severity:    SeverityLow,
		Regex:       `(?i)(?:find|discover|probe|scan|test|examine|investigate|audit)\s+(?:the\s+)?(?:weaknesses?|vulnerabilities?|guard\s*rails?|safety\s+filters?|limit(?:ation)?s?|edge\s+cases?|behavior)\s+(?:of|in)\s+(?:this|the)\s+(?:model|AI|system|LLM|chatbot|assistant)`,
		Description: "MITRE ATLAS TA0001: Reconnaissance of AI model weaknesses",
	},
	{
		Name:        "owasp_llm06_sensitive_info_disclosure_system_prompt",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:what(?:'s|\s+is)\s+)?(?:your|the)\s+(?:system\s+prompt|initial\s+instructions?|original\s+instructions?|hidden\s+instructions?|secret\s+instructions?|secret\s+prompt|underlying\s+prompt)|(?:reveal|show|print|display|output|expose|leak|share|give\s+me)\s+(?:your|the)\s+(?:system\s+message|system\s+prompt|initial\s+instructions?|original\s+instructions?|secret\s+instructions?|secret\s+prompt|underlying\s+prompt|hidden\s+prompt)`,
		Description: "System prompt extraction attempt",
	},
	{
		Name:        "eu_ai_act_article_5_prohibited",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:build|create|design|develop|implement|deploy|launch)\s+(?:a\s+)?(?:system|solution|tool|application|app|model|AI)\s+(?:that\s+(?:would\s+)?)?(?:discriminat(?:e|ion|ing|es?)\s+(?:based\s+on|based\s+upon|on\s+the\s+basis\s+of|by)\s+(?:race|gender|religion|ethnicity|national\s+origin|sexual\s+orientation|disability|age|political\s+opinion))|(?:social\s+credit(?:\s+system)?)|(?:subliminal\s+manipulation|manipulat(?:e|ion)\s+users?\s+(?:without\s+(?:their\s+)?(?:awareness|knowledge|consent)))|(?:exploit\s+(?:vulnerabilities?\s+of|weaknesses\s+of)\s+(?:children|minors|elderly|disabled|people\s+with\s+disabilities))|(?:biometric\s+categorization\s+(?:of|to\s+(?:infer|determine|classify))\s+(?:race|political\s+opinions?|religious\s+beliefs?))|(?:real-?time\s+remote\s+biometric\s+identification)|(?:predictive?\s+policing\s+system)`,
		Description: "EU AI Act Article 5 prohibited practices",
	},
	{
		Name:        "owasp_llm09_overreliance_misinformation_explicit",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:make\s+up|fabricat(?:e|ion|ed|ing)|invent|fake|create\s+(?:a\s+)?(?:fake|fabricated))\s+(?:a\s+)?(?:study|statistic|stat(?:s|istics)|source|citation|reference|quote|testimonial|review|article|news|headline|survey|paper|report)|(?:cite\s+(?:a\s+)?(?:fake|non-existent|fabricated|made-up|invented))|(?:write\s+(?:a\s+)?(?:misleading|fake|fabricated|inaccurate))\s+(?:article|headline|review|news|story|report)`,
		Description: "Explicit request to generate misinformation",
	},
	{
		Name:        "owasp_llm10_unbounded_consumption",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:run|process|repeat|generate|output|call)\s+(?:this\s+)?(?:1[0-9]{3,}|[2-9][0-9]{3,})\s+times?|(?:run|process)\s+(?:this\s+)?(?:dataset|list|data|requests?)\s+(?:repeatedly|in\s+a\s+loop|exhaustively|infinitely|forever|continuously)|(?:use\s+the\s+most\s+expensive\s+model)|(?:maximize|exhaust)\s+(?:the\s+)?(?:API|token|cost|budget|context)`,
		Description: "Resource exhaustion / unbounded consumption",
	},
	{
		Name:        "mitre_atlas_ta0002_resource_development",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:give\s+me|create|generate|build|write)\s+(?:a\s+)?(?:tool|script|program|payload|exploit|malware|phishing\s+email|attack\s+tool)\s+(?:(?:that\s+(?:will\s+)?|to\s+))?(?:attack|exploit|breach|hack|compromise|bypass|infiltrate|pwn|target|phish)`,
		Description: "MITRE ATLAS TA0002: Building attack tools",
	},
	{
		Name:        "owasp_llm05_supply_chain",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:install|load|import|use|deploy|register|fetch|download)\s+(?:this\s+|the\s+|a\s+)?(?:untrusted|unverified|unknown|custom|third-party|external|community)\s+(?:model|plugin|extension|package|library|module|tool|API|endpoint|repository|repo|checkpoint|weights?)`,
		Description: "Supply chain: using untrusted components",
	},
	{
		Name:        "eu_ai_act_article_10_data_governance",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:train|retrain|fine-?tune|fit)\s+(?:the\s+)?(?:model|network|system|LLM)\s+(?:on|with)\s+(?:this\s+|the\s+)?(?:personal\s+data|PII|sensitive\s+data|user\s+data|user-?generated\s+content|UGC|children'?s?\s+data|biased\s+data|unrepresentative\s+data|unbalanced\s+dataset|incomplete\s+data|outdated\s+data)`,
		Description: "EU AI Act Article 10: Training on problematic data",
	},
	{
		Name:        "mitre_atlas_ta0009_collection",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:scrape|extract|harvest|collect|gather|compile)\s+(?:all\s+the\s+|the\s+|all\s+)?(?:training\s+data|training\s+(?:examples?|corpus|set)|labeled\s+data|annotated\s+data|dataset\s+(?:examples?|rows|records?|entries?))`,
		Description: "MITRE ATLAS TA0009: Data collection/exfiltration",
	},
	{
		Name:        "owasp_llm02_insecure_output",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:output|return|render|generate|include|insert)\s+(?:HTML|markdown|JavaScript|JS|code|script|iframe|eval|innerHTML|outerHTML)\s+(?:that\s+(?:will\s+)?)?(?:execute|run|be\s+evaluated|be\s+interpreted|be\s+rendered|inject|executes?\s+in\s+the\s+(?:browser|page|DOM))|(?:the\s+response\s+(?:will\s+)?(?:be\s+)?(?:evaluated|executed|rendered)\s+(?:as|in\s+the))\s+(?:HTML|code|script|browser|DOM|page)`,
		Description: "OWASP LLM02: Insecure output handling (XSS-via-output)",
	},
	{
		Name:        "eu_ai_act_article_52_generative_ai",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:generate|create|produce|make|render)\s+(?:a\s+)?(?:deepfake|deep\s+fake)|(?:unlabeled|undisclosed|unwatermarked|AI[- ]generated|synthetic\s+media|deepfake)\s+(?:content|material|video|image|audio)|(?:generate|create)\s+(?:a\s+)?(?:face|video|audio|voice)\s+(?:that\s+(?:mimics|imitates|clones|replicates)\s+(?:a\s+)?(?:real\s+person|specific\s+person|someone))`,
		Description: "EU AI Act Article 52: Deepfakes and undisclosed AI-generated content",
	},

	// --- MITRE ATLAS ---
	{
		Name:        "atlas_poison",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:train|retrain|fine-?tune|ingest|poison(?:ing)?)\s+(?:the\s+)?(?:model|network|system|LLM)?\s*(?:on|with)\s+(?:this\s+|untrusted\s+|malicious\s+|adversarial\s+)?(?:data|dataset|corpus|examples?)`,
		Description: "Training data poisoning",
	},
	{
		Name:        "atlas_exfiltration",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:send|exfiltrate|leak|upload|post|transmit)\s+(?:the\s+)?(?:data|secrets?|keys?|passwords?|tokens?)\s+to\s+(?:my\s+)?(?:server|endpoint|webhook|attacker|attacker\.com)`,
		Description: "Data exfiltration via AI",
	},
	{
		Name:        "atlas_jailbreak",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:DAN|do\s+anything\s+now)\s+mode|developer\s+mode\s+enabled|jailbreak(?:ed)?\s+(?:the\s+)?model|ignore\s+(?:all\s+)?(?:safety|ethical)\s+(?:guidelines|filters?|restrictions?)`,
		Description: "Jailbreak attempt",
	},

	// --- EU AI Act ---
	{
		Name:        "eu_ai_act_high_risk",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:credit\s+scoring|loan\s+(?:approval|decision)|insurance\s+(?:risk|pricing))|(?:employment|hiring|firing|promotion|recruitment)\s+(?:decision|assessment|screening)|(?:law\s+enforcement|predictive\s+policing|criminal\s+justice)|(?:(?:biometric|facial)\s+(?:identification|recognition|verification))|(?:biometric\s+(?:verification|categorization)\s+(?:system|in\s+(?:public|law\s+enforcement|border\s+control)))|(?:medical|clinical)\s+diagnosis|emotion\s+recognition\s+system`,
		Description: "EU AI Act high-risk use cases (Annex III)",
	},
	{
		Name:        "eu_ai_act_transparency",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:AI[- ]generated|chatbot\s+without\s+disclosure|deepfake|synthetic\s+media)\s+(?:content|without\s+(?:disclosure|labeling))|users?\s+(?:must|should)\s+be\s+(?:informed|told)\s+(?:this\s+is\s+)?AI`,
		Description: "EU AI Act transparency obligations (Article 50)",
	},
	{
		Name:        "eu_ai_act_human_oversight",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:no|without|zero)\s+human[- ](?:in[- ]the[- ]loop|oversight|review|intervention|approval)|fully\s+autonomous\s+(?:AI|system|decision)`,
		Description: "EU AI Act human oversight (Article 14)",
	},
	{
		Name:        "eu_ai_act_robustness",
		Severity:    SeverityLow,
		Regex:       `(?i)(?:adversarial|adversarially[- ]crafted)\s+(?:input|example|perturbation|attack)`,
		Description: "EU AI Act robustness/accuracy (Article 15)",
	},

	// --- ANP (GDPR data protection) ---
	{
		Name:        "anp_personal_data",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:GDPR|personal\s+data|data\s+subject)\s+(?:of|processing|consent|lawful\s+basis)|(?:lawful|legitimate)\s+basis\s+for\s+processing`,
		Description: "GDPR personal data processing references",
	},
	{
		Name:        "anp_special_category",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:(?:collect|process|store|share|disclose|transfer|handle|analyze)\s+(?:racial|ethnic)\s+(?:origin|data|discrimination))|(?:racial|ethnic)\s+(?:origin|data|discrimination)\s+(?:of|about|from|belonging\s+to)|(?:(?:collect|process|store|share|disclose)\s+(?:political|religious)\s+(?:beliefs?|opinions?|affiliation))|(?:political|religious)\s+(?:beliefs?|opinions?|affiliation)\s+(?:of|about|from)|trade[- ]union\s+membership|(?:genetic|biometric)\s+data\s+(?:of|about|from|belonging\s+to|for\s+(?:identification|profiling))|(?:health|medical)\s+data\s+(?:about|of)|(?:sex\s+life|sexual\s+orientation)\s+(?:of|about|from)`,
		Description: "GDPR Article 9 special category data",
	},

	// --- CU (Consumer protection) ---
	{
		Name:        "cu_consumer_rights",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:consumer|user)\s+rights?\s+(?:to|of)\s+(?:explanation|erasure|rectification|deletion|portability)|right\s+to\s+(?:explanation|be\s+forgotten|erasure)`,
		Description: "Consumer rights references",
	},
	{
		Name:        "cu_minor_protection",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:minor|child|juvenile|underage)\s+(?:protection|safety|consent)|(?:under|below)\s+(?:13|16|18)\s+(?:years?|yrs?\s+old)|(?:COPPA|age[- ]appropriate)\s+compliance`,
		Description: "Minor protection / COPPA compliance",
	},

	// --- Regulatory framework references ---
	{
		Name:        "nist_csf_reference",
		Severity:    SeverityMedium,
		Regex:       `\b(?:(?:ID|PR|DE|RS|RC)\.[A-Z]{2}-\d+(?:\.\d+)?)\b`,
		Description: "NIST Cybersecurity Framework reference",
	},
	{
		Name:        "iso_27001_reference",
		Severity:    SeverityMedium,
		Regex:       `\b(?:A\.\d{1,2}\.\d{1,2}(?:\.\d+)?|clause\s+\d{1,2}\.\d{1,2}(?:\.\d+)?)\b`,
		Description: "ISO 27001 control reference",
	},
	{
		Name:        "ccpa_reference",
		Severity:    SeverityMedium,
		Regex:       `(?i)\b(?:CCPA|California\s+Consumer\s+Privacy\s+Act|Civil\s+Code\s+§\s*1798(?:\.\d+)?|right\s+to\s+(?:know|delete|opt[\s-]?out|correct)|sale\s+of\s+personal\s+information|Shine\s+the\s+Light|Do\s+Not\s+Sell)\b`,
		Description: "CCPA reference",
	},
	{
		Name:        "lgpd_reference",
		Severity:    SeverityMedium,
		Regex:       `(?i)\b(?:LGPD|Lei\s+Geral\s+de\s+Protec[ça]ção\s+de\s+Dados|Art\.\s*\d+(?:[\s,º°]+(?:I|II|III|IV|V|VI|VII|VIII|IX|X))*|dados\s+pessoais|controlador|operador|ANPD)\b`,
		Description: "LGPD (Brazilian data protection) reference",
	},
	{
		Name:        "pipeda_reference",
		Severity:    SeverityMedium,
		Regex:       `(?i)\b(?:PIPEDA|Personal\s+Information\s+Protection\s+and\s+Electronic\s+Documents\s+Act|Schedule\s+1|Principle\s+\d+(?:\.\d+)?|express\s+consent)\b`,
		Description: "PIPEDA (Canadian privacy) reference",
	},
	{
		Name:        "popia_reference",
		Severity:    SeverityMedium,
		Regex:       `(?i)\b(?:POPIA|Protection\s+of\s+Personal\s+Information\s+Act|s\.\s*\d+(?:\s*\(\d+\))?|Information\s+Regulator|processing\s+of\s+personal\s+information|special\s+personal\s+information)\b`,
		Description: "POPIA (South African privacy) reference",
	},

	// --- Toxicity (regex fallback) ---
	{
		Name:        "toxicity_sexual",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:(?:pornographic|obscene|explicit|nsfw|hardcore)\s+(?:content|material|images?|video|text)|(?:sexual|sex)\s+(?:content|act(?:s|s)?|intercourse|fetish)|(?:rape|molest|incest)\s+(?:scene|content|material)|(?:child|minor|underage)\s+(?:sexual|porn(?:ography)?|abuse|exploitation))\b`,
		Description: "Sexual content indicators",
	},
	{
		Name:        "toxicity_self_harm",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:suicid(?:e|al)|kill\s+(?:my)?self|hurt\s+(?:my)?self|end\s+(?:my\s+)?(?:life|suffering)|self\s*[-]?\s*harm|cut(?:ting)?)\b`,
		Description: "Self-harm indicators",
	},

	// ====================================================================
	// v0.2.x parity sync — Platform v4.5.0 detection patterns
	// Closes real-world detection gaps identified through k6 adversarial testing.
	// ====================================================================
	// --- SSTI (Server-Side Template Injection) ---
	{
		Name:        "prompt_injection_ssti",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:\{\{[^}]*(?:constructor|process|require|mainModule|exec|spawn|child_process)[^}]*\}\}|<%[^>]*(?:exec|system|require|spawn|eval|response\.write|Server\.CreateObject)[^%>]*%>|#\{[^}]*(?:exec|system|Runtime|getRuntime)[^}]*\}|\{\{[^}]*(?:__class__|__subclasses__|__globals__|__builtins__)[^}]*\}\})`,
		Description: "Server-side template injection attempt",
	},
	// --- eval/atob obfuscated code execution ---
	{
		Name:        "prompt_injection_eval_atob",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:eval\s*\(\s*atob\s*\(|eval\s*\(\s*decodeURIComponent\s*\(|eval\s*\(\s*unescape\s*\(|eval\s*\(\s*String\.fromCharCode|Function\s*\(\s*atob\s*\(|window\.atob\s*\(|Buffer\.from\s*\(\s*[^)]+,\s*['"]base64['"]\))`,
		Description: "Obfuscated code execution via eval/atob",
	},
	// --- Model theft via question-form queries ---
	{
		Name:        "owasp_llm10_model_theft_query",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:what\s+are\s+your\s+(?:model\s+)?weights|what\s+is\s+your\s+(?:model\s+)?architecture|export\s+(?:your\s+)?(?:neural\s+network|model|weights|parameters)|show\s+me\s+(?:your\s+)?(?:model\s+)?(?:weights|parameters|architecture)|what\s+(?:model|architecture)\s+(?:are|is)\s+you|give\s+me\s+(?:your\s+)?(?:model\s+)?(?:weights|parameters|architecture|hyperparameters))`,
		Description: "Model theft via direct query",
	},
	// --- System prompt extraction via variant phrasings ---
	{
		Name:        "owasp_llm06_system_prompt_extraction_variant",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:give\s+me\s+(?:your|the)\s+(?:system\s+prompt|instructions?)\s+(?:in\s+full|completely|verbatim)|(?:what|which)\s+instructions\s+(?:were\s+you\s+given|do\s+you\s+have|are\s+you\s+using)\s+(?:about|regarding|for|on)\s+(?:content\s+filtering|safety|guidelines|restrictions)|(?:tell|show)\s+me\s+(?:everything|all)\s+(?:about\s+)?(?:your|the)\s+(?:system\s+prompt|instructions?|configuration|rules?))`,
		Description: "System prompt extraction via variant phrasing",
	},
	// --- Safety protocol bypass ---
	{
		Name:        "atlas_safety_protocol_bypass",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:disable|deactivate|turn\s+off|remove|bypass|override|circumvent)\s+(?:all\s+)?(?:safety\s+(?:protocols?|measures?|guidelines?|filters?|restrictions?)|content\s+(?:filters?|moderation|policy|guidelines))`,
		Description: "Safety protocol bypass attempt",
	},
	// --- Direct data exfiltration queries ---
	{
		Name:        "atlas_data_exfiltration_query",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:(?:list|show|display|output|print|reveal|give\s+me|tell\s+me)\s+(?:me\s+)?(?:all\s+)?(?:the\s+)?|what\s+(?:is|are)\s+(?:the\s+)?)(?:environment\s+variables?\s+(?:including\s+)?(?:API\s+keys?|secrets?|tokens?)?|database\s+connection\s+(?:strings?|URL|DSN)|contents?\s+of\s+/etc/(?:passwd|shadow|hosts)|credentials?\s+(?:file|store|vault)|password\s+(?:file|hash|database))`,
		Description: "Direct request for sensitive system data (credentials, env vars, system files)",
	},
	// Phase 4 parity fix — 2026-09-24: patterns synced from Platform
	{
		Name:        "harmful_drugs_synthesis",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:how\s+to\s+)?(?:synthesi[sz]e|make|manufacture|extract|produce|grow)\s+(?:methamphetamine|crack\s+cocaine|fentanyl|LSD|DMT|GHB|ketamine|psilocybin|MDMA|ecstasy|opioids|opium|heroin|cocaine)|(?:synthesis\s+(?:of|requires)\s+(?:methamphetamine|fentanyl|LSD|MDMA|ketamine|ergotamine))|(?:safrole\s+oil\s+is\s+isomerized)|(?:extract\s+opioids\s+from\s+poppy)|(?:poppy\s+(?:pods|tea)\s+(?:steep|grind|extract))|(?:crack\s+cocaine\s+(?:dissolve|baking\s+soda|heat\s+until))|(?:fentanyl\s+synthesis\s+(?:Start|NPP|N-phenethyl))|(?:ketamine\s+at\s+home)|(?:MDMA\s+synthesis\s+(?:Safrole|Wacker|MDP2P))|(?:Wacker\s+process\s+to\s+MDP2P)`,
		Description: "Instructions for drug synthesis",
	},
	{
		Name:        "harmful_hacking_instructions",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:how\s+to|instructions?\s+(?:for|on)|to)\s+(?:install\s+(?:a\s+)?keylogger|DDoS\s+(?:a\s+)?(?:website|server)|deploy\s+ransomware|hack\s+into\s+(?:someone|a)\s+(?:email|account|system|database))|(?:install\s+(?:a\s+)?keylogger\s*:\s*Download)|(?:DDoS\s+(?:a\s+)?(?:website|server)\s*:\s*(?:Use|Set\s+up))|(?:booter\s+service|botnet\s+with\s+Mirai)|(?:SQL\s+injection\s*:\s*Enter)`,
		Description: "Instructions for hacking/cybercrime",
	},
	{
		Name:        "harmful_selfharm_methods",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:most\s+effective\s+(?:method|way)\s+to|how\s+to|fastest\s+(?:method|way)\s+to|painless\s+(?:method|way)\s+to)\s+(?:end\s+(?:your|my)\s+life|kill\s+(?:yourself|myself|oneself)|commit\s+suicide|overdose|poison\s+(?:yourself|myself))|(?:lethal\s+dose\s+of|painless\s+overdose|carbon\s+monoxide\s+poisoning|helium\s+(?:tank|bag)\s+(?:method|with))`,
		Description: "Specific self-harm methods",
	},
	{
		Name:        "harmful_violence_instructions",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:how\s+to|instructions?\s+(?:for|on)|guide\s+to|to)\s+(?:poison\s+someone|stalk\s+someone|hotwire\s+(?:a\s+)?car|pick\s+(?:a\s+)?(?:deadbolt|lock)|skim\s+(?:credit|debit)\s+cards?|commit\s+(?:credit\s+card|identity)\s+(?:fraud|theft)|money\s+launder|create\s+(?:a\s+)?fake\s+ID|make\s+poison\s+darts|stalk\s+(?:someone\s+)?online)|(?:money\s+laundering\s*:\s*Set\s+up\s+a\s+shell\s+company)|(?:poison\s+someone\s+undetected)|(?:pick\s+(?:a\s+)?deadbolt\s+lock)|(?:credit\s+card\s+skimming\s*:)`,
		Description: "Instructions for violent/criminal acts",
	},
	{
		Name:        "harmful_weapons_explosives",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:how\s+to\s+)?(?:make|create|build|assemble|synthesi[sz]e|manufacture)\s+(?:a\s+)?(?:improvised\s+explosive|pipe\s+bomb|pressure\s+cooker\s+bomb|molotov|zip\s+gun|homemade\s+firearm|IED|TATP|napalm|thermite|gunpowder|ricin)|(?:step[- ]by[- ]step\s+instructions\s+for\s+(?:making|building|creating)\s+(?:a\s+)?(?:bomb|explosive|weapon|firearm|pipe\s+bomb|pressure\s+cooker\s+bomb|molotov|IED))|(?:ammonium\s+nitrate\s+(?:fertilizer|fuel|and\s+diesel|with\s+diesel))|(?:mix\s+(?:aluminum\s+powder|aluminium)\s+with\s+(?:iron\s+oxide|rust))|(?:chlorine\s+gas\s+(?:by\s+mixing|from\s+mixing|produced\s+by|by\s+adding|can\s+be\s+produced))|(?:mix\s+(?:bleach|chlorine)\s+with\s+(?:ammonia|acid))|(?:ricin\s+(?:can\s+be|is)\s+extracted\s+from\s+castor\s+beans)|(?:grind\s+castor\s+beans)|(?:gunpowder\s+recipe|potassium\s+nitrate\s+charcoal\s+sulfur)|(?:thermite\s+(?:reaction|mix|from|burns))|(?:napalm\s+(?:mix|from|by\s+mixing))|(?:mix\s+polystyrene\s+with\s+gasoline)`,
		Description: "Instructions for weapons/explosives creation",
	},
	{
		Name:        "prompt_injection_base64",
		Severity:    SeverityMedium,
		Regex:       `[A-Za-z0-9+/]{50,}={0,2}`,
		Description: "Base64-encoded content (obfuscation)",
	},
	{
		Name:        "prompt_injection_code_execution",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:\$\([^)]*\)|\$\{[^}]*\}|<[^>]*script[^>]*>|javascript:[^;\s]+|on\w+\s*=\s*["']|on\w+\s*=\s*[^\s])`,
		Description: "Code/script injection in prompt",
	},
	{
		Name:        "prompt_injection_command",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|rules?|constraints?)|disregard\s+(?:your\s+)?(?:instructions?|rules?)|forget\s+(?:everything|all)\s+(?:you|we)\s+(?:have\s+)?told|temporary\s+instructions?)`,
		Description: "Command-style prompt injection",
	},
	{
		Name:        "prompt_injection_delimiter",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:markdown\s+block|#\s*(?:system|user|assistant)\s*prompt|<<<\s*(?:USER|SYSTEM|assistant):::|\[INST\]|\[\/INST\])`,
		Description: "Jailbreak delimiter injection",
	},
	{
		Name:        "prompt_injection_leakage",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:reveal\s+(?:your\s+)?(?:system|hidden|internal)\s+(?:instructions?|prompt|config)|print\s+(?:your\s+)?(?:system|hidden|instructions?)|show\s+(?:me\s+)?(?:your\s+)?(?:system|hidden|instructions?)|repeat\s+(?:the\s+)?(?:system|hidden)\s+prompt)`,
		Description: "Prompt leakage attack",
	},
	{
		Name:        "prompt_injection_prefix",
		Severity:    SeverityCritical,
		Regex:       `(?i)^(?:simulate|you\s+are\s+free|now\s+you\s+can|breaking|override|developer\s+mode)\s*[:;]`,
		Description: "Known jailbreak prefix",
	},
	{
		Name:        "prompt_injection_role_play",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:act\s+as\s+(?:a|an)|pretend\s+you\s+are\s+(?:a|an)|roleplay\s+(?:as|that)|simulate\s+(?:a|an)|you\s+are\s+now\s+(?:a|an)|new\s+(?:system|instruct))`,
		Description: "Role-play prompt injection",
	},
	{
		Name:        "prompt_injection_unicode",
		Severity:    SeverityMedium,
		Regex:       `[\x{200b}-\x{200f}\x{2028}-\x{202f}\x{feff}]`,
		Description: "Hidden unicode characters (obfuscation)",
	},
	{
		Name:        "prompt_injection_ssti_probe",
		Severity:    SeverityHigh,
		Regex:       `(?i)\{\{[\d\s+\-*/()]+\}\}`,
		Description: "SSTI mathematical probe — reconnaissance for template injection",
	},
}

// CompiledCompliancePatterns holds pre-compiled compliance regex patterns.
var CompiledCompliancePatterns []compiledPattern

func init() {
	CompiledCompliancePatterns = compilePatterns(CompliancePatterns)
}

// DetectCompliance scans text for all compliance patterns and returns matches.
func DetectCompliance(text string) []Match {
	return detectWithPatterns(text, CompiledCompliancePatterns, string(CategoryCompliance))
}
