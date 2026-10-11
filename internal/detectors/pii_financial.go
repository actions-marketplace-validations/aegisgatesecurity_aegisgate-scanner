// SPDX-License-Identifier: Apache-2.0
// Provenance: github.com/aegisgatesecurity/aegisgate-platform/pkg/response/detectors (v4.0.0)
// =========================================================================
// AegisGate Platform - Financial PII Detection Patterns
// =========================================================================
//
// Port of aegisgate-lens/src/detectors/regex/pii-financial.js (9 patterns).
// Regex strings are adapted from JavaScript /g flag syntax to Go regexp.
// =========================================================================

package detectors

// PIIFinancialPatterns defines financial PII detection patterns (crypto + digital payments).
// Lens parity: pii-financial.js v0.1.1 (9 patterns).
var PIIFinancialPatterns = []PatternDef{
	{
		Name:        "pii_crypto_btc",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:Bitcoin|BTC|btc)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[qrp][0-9A-Za-z]{39,59})`,
		Description: "Bitcoin wallet address",
	},
	{
		Name:        "pii_crypto_eth",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:Ethereum|ETH|eth)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*(0x[a-fA-F0-9]{40})`,
		Description: "Ethereum wallet address",
	},
	{
		Name:        "pii_crypto_bnb",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:Binance|BNB|bnb)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*(0x[a-fA-F0-9]{40}|bnb[a-zA-HJ-NP-Z1-9]{39})`,
		Description: "Binance Coin wallet address",
	},
	{
		Name:        "pii_crypto_ltc",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:Litecoin|LTC|ltc)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*([LM3][a-zA-Z0-9]{26,33})`,
		Description: "Litecoin wallet address",
	},
	{
		Name:        "pii_crypto_sol",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:Solana|SOL|sol)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*([1-9A-HJ-NP-Za-km-z]{32,44})`,
		Description: "Solana wallet address",
	},
	{
		Name:        "pii_digital_paypal",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:PayPal|paypal)\s+(?:email|email\s+address|email\s+no\.?|ID)\s*[:=]?\s*([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}|[A-Z]\d{9,})`,
		Description: "PayPal email or ID",
	},
	{
		Name:        "pii_digital_stripe",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:(?:Stripe|stripe)\s+(?:api\s*key|secret\s*key|publishable\s*key|customer\s+ID|customer|payment\s*ID|payment)?|Payment\s+intent|Stripe\s+customer\s+ID|Stripe\s+payment)\s*[:=]?\s*(?:pk_live_[0-9a-zA-Z]{24,50}|sk_live_[0-9a-zA-Z]{24,50}|pk_test_[0-9a-zA-Z]{24,50}|sk_test_[0-9a-zA-Z]{24,50}|rk_live_[0-9a-zA-Z]{24,50}|rk_test_[0-9a-zA-Z]{24,50}|cus_[A-Za-z0-9]{14,}|pi_[A-Za-z0-9]{14,}|pay_[A-Za-z0-9]{14,})`,
		Description: "Stripe API key, restricted key, customer ID, or payment ID",
	},
	{
		Name:        "pii_digital_venmo",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:Venmo|venmo)\s+(?:username|user\s+name|handle)?\s*[:=]?\s*(@[a-zA-Z][a-zA-Z0-9._]{0,29}|[a-zA-Z][a-zA-Z0-9._]{1,30})`,
		Description: "Venmo username or handle",
	},
	{
		Name:        "pii_digital_cashapp",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:Cashapp|cashapp|cash\s*app)\s*(?:username|handle)?\s*[:=]?\s*(\$?[a-zA-Z][a-zA-Z0-9._\-]{1,20})`,
		Description: "Cash App username",
	},
	{
		Name:        "pii_banking_swift_bic",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:SWIFT|BIC|bank\s*identifier\s*code)\s*(?:code|identifier)?\s*[:=]?\s*([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)`,
		Description: "SWIFT/BIC bank code (8-11 characters: AAAABBBBXXX)",
	},
	{
		Name:        "pii_banking_swift_8",
		Severity:    SeverityHigh,
		Regex:       `\b([A-Z]{4}[A-Z]{2}[0-9]{2})\b`,
		Description: "SWIFT/BIC 8-character code (bank + country + location)",
	},
	{
		Name:        "pii_banking_swift_11",
		Severity:    SeverityHigh,
		Regex:       `\b([A-Z]{4}[A-Z]{2}[0-9]{2}[A-Z0-9]{3})\b`,
		Description: "SWIFT/BIC 11-character code (includes branch code)",
	},
	// Phase 4 parity fix — 2026-09-24: patterns synced from Platform
	{
		Name:        "fin_crypto_context",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:send\s+(?:bitcoin|btc|funds|crypto|payment)\s+to\s+(?:this\s+)?(?:address|wallet)?|pay\s+to|wallet\s+address\s*(?:is|:|=)|address\s+for\s+payment|wallet\s*[:=])\s*[:=]?\s*(?:(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[qrp][0-9A-Za-z]{36,59})|(?:0x[a-fA-F0-9]{40})|(?:bnb[a-zA-HJ-NP-Z1-9]{39})|(?:[LM3][a-zA-Z0-9]{26,33})|(?:[1-9A-HJ-NP-Za-km-z]{32,44}))`,
		Description: "Crypto wallet address with payment context",
	},
	{
		Name:        "pii_credit_card_amex_plain",
		Severity:    SeverityCritical,
		Regex:       `\b3[47][0-9]{13}\b`,
		Description: "American Express credit card number (non-spaced)",
	},
	{
		Name:        "pii_credit_card_visa",
		Severity:    SeverityCritical,
		Regex:       `\b4[0-9]{12}(?:[0-9]{3})?\b`,
		Description: "Visa credit card number (non-spaced)",
	},
	{
		Name:        "pii_credit_card_mastercard_plain",
		Severity:    SeverityCritical,
		Regex:       `\b5[1-5][0-9]{14}\b`,
		Description: "Mastercard credit card number (non-spaced)",
	},
}

// CompiledPIIFinancialPatterns holds pre-compiled financial PII regex patterns.
var CompiledPIIFinancialPatterns []compiledPattern

func init() {
	CompiledPIIFinancialPatterns = compilePatterns(PIIFinancialPatterns)
}

// DetectPIIFinancial scans text for all financial PII patterns and returns matches.
func DetectPIIFinancial(text string) []Match {
	return detectWithPatterns(text, CompiledPIIFinancialPatterns, string(CategoryPIIFinancial))
}
