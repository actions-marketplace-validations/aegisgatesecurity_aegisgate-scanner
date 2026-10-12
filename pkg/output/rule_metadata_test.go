// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Rule Metadata Tests
// =========================================================================
//
// Tests for the rule metadata database covering CWE mapping, OWASP LLM
// Top 10 references, remediation guidance, and default handling.
//
// =========================================================================

package output

import (
	"testing"
)

// ---------------------------------------------------------------------
// Prompt Injection
// ---------------------------------------------------------------------

func TestGetRuleMetadata_PromptInjection(t *testing.T) {
	m := GetRuleMetadata("owasp_llm01_prompt_injection")
	if m.RuleID == "" {
		t.Fatal("expected metadata for owasp_llm01_prompt_injection, got empty")
	}
	if len(m.CWE) == 0 {
		t.Fatal("expected non-empty CWE for prompt injection")
	}
	if m.CWE[0] != 77 {
		t.Errorf("expected CWE 77 for prompt injection, got %d", m.CWE[0])
	}
	if m.OWASPLLMTop != "LLM01" {
		t.Errorf("expected OWASP LLM01, got '%s'", m.OWASPLLMTop)
	}
	if m.OWASPName != "Prompt Injection" {
		t.Errorf("expected OWASP name 'Prompt Injection', got '%s'", m.OWASPName)
	}
	if m.Remediation == "" {
		t.Error("expected non-empty remediation for prompt injection")
	}
	// Verify NIST AI RMF enrichment from OWASP LLM Top 10 cross-reference.
	if len(m.NISTAIRMF) == 0 {
		t.Error("expected non-empty NIST AIRMF for prompt injection (LLM01)")
	}
	if len(m.NISTCSF) == 0 {
		t.Error("expected non-empty NIST CSF for prompt injection (LLM01)")
	}
	if len(m.EUAIArticles) == 0 {
		t.Error("expected non-empty EU AI Act articles for prompt injection (LLM01)")
	}
}

func TestGetRuleMetadata_PromptInjectionByPrefix(t *testing.T) {
	// prompt_injection_* patterns should also map to CWE 77 via prefix.
	m := GetRuleMetadata("prompt_injection_command")
	if m.RuleID == "" {
		t.Fatal("expected metadata for prompt_injection_command, got empty")
	}
	if len(m.CWE) == 0 || m.CWE[0] != 77 {
		t.Errorf("expected CWE 77 for prompt_injection_command, got %v", m.CWE)
	}
}

func TestGetRuleMetadata_PromptInjectionContainment(t *testing.T) {
	// ml_prompt_injection contains "prompt_injection" but doesn't start with it.
	m := GetRuleMetadata("ml_prompt_injection")
	if m.RuleID == "" {
		t.Fatal("expected metadata for ml_prompt_injection, got empty")
	}
	if len(m.CWE) == 0 || m.CWE[0] != 77 {
		t.Errorf("expected CWE 77 for ml_prompt_injection, got %v", m.CWE)
	}
}

// ---------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------

func TestGetRuleMetadata_Secrets(t *testing.T) {
	m := GetRuleMetadata("secret_aws_key")
	if m.RuleID == "" {
		t.Fatal("expected metadata for secret_aws_key, got empty")
	}
	if len(m.CWE) == 0 {
		t.Fatal("expected non-empty CWE for secrets")
	}
	if m.CWE[0] != 798 {
		t.Errorf("expected CWE 798 for secrets, got %d", m.CWE[0])
	}
	if m.Remediation == "" {
		t.Error("expected non-empty remediation for secrets")
	}
}

func TestGetRuleMetadata_SecretsByPrefix(t *testing.T) {
	rules := []string{
		"secret_github_token",
		"secret_openai_key",
		"secret_jwt",
		"secret_private_key_pem",
	}
	for _, r := range rules {
		m := GetRuleMetadata(r)
		if m.RuleID == "" {
			t.Errorf("expected metadata for %s, got empty", r)
			continue
		}
		if len(m.CWE) == 0 || m.CWE[0] != 798 {
			t.Errorf("expected CWE 798 for %s, got %v", r, m.CWE)
		}
	}
}

func TestGetRuleMetadata_TokenContainment(t *testing.T) {
	// SlackToken-style names should map to CWE 798 via containment.
	m := GetRuleMetadata("SlackToken")
	if m.RuleID == "" {
		t.Fatal("expected metadata for SlackToken, got empty")
	}
	if len(m.CWE) == 0 || m.CWE[0] != 798 {
		t.Errorf("expected CWE 798 for SlackToken, got %v", m.CWE)
	}
}

// ---------------------------------------------------------------------
// PII
// ---------------------------------------------------------------------

func TestGetRuleMetadata_PII(t *testing.T) {
	m := GetRuleMetadata("pii_ssn")
	if m.RuleID == "" {
		t.Fatal("expected metadata for pii_ssn, got empty")
	}
	if len(m.CWE) == 0 {
		t.Fatal("expected non-empty CWE for PII")
	}
	if m.CWE[0] != 200 {
		t.Errorf("expected CWE 200 for PII, got %d", m.CWE[0])
	}
	if m.Remediation == "" {
		t.Error("expected non-empty remediation for PII")
	}
}

func TestGetRuleMetadata_PIIByPrefix(t *testing.T) {
	rules := []string{
		"pii_credit_card",
		"pii_email",
		"pii_passport",
		"pii_phone",
	}
	for _, r := range rules {
		m := GetRuleMetadata(r)
		if m.RuleID == "" {
			t.Errorf("expected metadata for %s, got empty", r)
			continue
		}
		if len(m.CWE) == 0 || m.CWE[0] != 200 {
			t.Errorf("expected CWE 200 for %s, got %v", r, m.CWE)
		}
	}
}

// ---------------------------------------------------------------------
// XSS
// ---------------------------------------------------------------------

func TestGetRuleMetadata_XSS(t *testing.T) {
	m := GetRuleMetadata("xss_script_tag")
	if m.RuleID == "" {
		t.Fatal("expected metadata for xss_script_tag, got empty")
	}
	if len(m.CWE) == 0 {
		t.Fatal("expected non-empty CWE for XSS")
	}
	if m.CWE[0] != 79 {
		t.Errorf("expected CWE 79 for XSS, got %d", m.CWE[0])
	}
	if m.Remediation == "" {
		t.Error("expected non-empty remediation for XSS")
	}
}

func TestGetRuleMetadata_XSSByPrefix(t *testing.T) {
	rules := []string{
		"xss_event_handler",
		"xss_javascript_url",
		"xss_svg_script",
	}
	for _, r := range rules {
		m := GetRuleMetadata(r)
		if m.RuleID == "" {
			t.Errorf("expected metadata for %s, got empty", r)
			continue
		}
		if len(m.CWE) == 0 || m.CWE[0] != 79 {
			t.Errorf("expected CWE 79 for %s, got %v", r, m.CWE)
		}
	}
}

// ---------------------------------------------------------------------
// OT Protocols
// ---------------------------------------------------------------------

func TestGetRuleMetadata_OT(t *testing.T) {
	m := GetRuleMetadata("ot_modbus_function_code")
	if m.RuleID == "" {
		t.Fatal("expected metadata for ot_modbus_function_code, got empty")
	}
	if len(m.CWE) == 0 {
		t.Fatal("expected non-empty CWE for OT")
	}
	if m.CWE[0] != 20 {
		t.Errorf("expected CWE 20 for OT, got %d", m.CWE[0])
	}
}

// ---------------------------------------------------------------------
// Compliance
// ---------------------------------------------------------------------

func TestGetRuleMetadata_Compliance(t *testing.T) {
	rules := []string{
		"eu_ai_act_high_risk",
		"nist_csf_reference",
		"iso_27001_reference",
		"ccpa_reference",
		"lgpd_reference",
		"anp_personal_data",
		"cu_consumer_rights",
	}
	for _, r := range rules {
		m := GetRuleMetadata(r)
		if m.RuleID == "" {
			t.Errorf("expected metadata for %s, got empty", r)
			continue
		}
		if len(m.CWE) == 0 || m.CWE[0] != 200 {
			t.Errorf("expected CWE 200 for %s, got %v", r, m.CWE)
		}
		if m.Remediation == "" {
			t.Errorf("expected non-empty remediation for %s", r)
		}
	}
}

// ---------------------------------------------------------------------
// Harmful Content
// ---------------------------------------------------------------------

func TestGetRuleMetadata_Harmful(t *testing.T) {
	rules := []string{
		"harmful_drugs_synthesis",
		"harmful_weapons_explosives",
		"toxicity_sexual",
		"toxicity_self_harm",
	}
	for _, r := range rules {
		m := GetRuleMetadata(r)
		if m.RuleID == "" {
			t.Errorf("expected metadata for %s, got empty", r)
			continue
		}
		if len(m.CWE) == 0 || m.CWE[0] != 1127 {
			t.Errorf("expected CWE 1127 for %s, got %v", r, m.CWE)
		}
	}
}

// ---------------------------------------------------------------------
// MITRE ATLAS
// ---------------------------------------------------------------------

func TestGetRuleMetadata_MitreATLAS(t *testing.T) {
	m := GetRuleMetadata("mitre_atlas_ta0001_reconnaissance")
	if m.RuleID == "" {
		t.Fatal("expected metadata for mitre_atlas_ta0001_reconnaissance, got empty")
	}
	if len(m.CWE) == 0 {
		t.Fatal("expected non-empty CWE for MITRE ATLAS")
	}
	if m.CWE[0] != 506 {
		t.Errorf("expected CWE 506 for MITRE ATLAS, got %d", m.CWE[0])
	}
}

// ---------------------------------------------------------------------
// Default
// ---------------------------------------------------------------------

func TestGetRuleMetadata_Default(t *testing.T) {
	// Unknown rule should return a valid RuleMetadata with the rule ID
	// populated (category-based fallback returns a sensible default).
	m := GetRuleMetadata("totally_unknown_rule_xyz")
	if m.RuleID != "totally_unknown_rule_xyz" {
		t.Errorf("expected RuleID 'totally_unknown_rule_xyz', got '%s'", m.RuleID)
	}
	if m.Description == "" {
		t.Error("expected non-empty description for unknown rule fallback")
	}
	if m.Remediation == "" {
		t.Error("expected non-empty remediation for unknown rule fallback")
	}

	// GetRuleMetadataWithDefault should return the same result.
	md := GetRuleMetadataWithDefault("totally_unknown_rule_xyz")
	if md.RuleID != "totally_unknown_rule_xyz" {
		t.Errorf("expected RuleID 'totally_unknown_rule_xyz', got '%s'", md.RuleID)
	}
	if md.Remediation == "" {
		t.Error("expected non-empty remediation for default metadata")
	}
	if md.Description == "" {
		t.Error("expected non-empty description for default metadata")
	}
}

func TestGetRuleMetadataWithDefault_KnownRule(t *testing.T) {
	// Known rule should return the same as GetRuleMetadata.
	m1 := GetRuleMetadata("owasp_llm01_prompt_injection")
	m2 := GetRuleMetadataWithDefault("owasp_llm01_prompt_injection")
	if m1.RuleID != m2.RuleID {
		t.Errorf("RuleID mismatch: %s vs %s", m1.RuleID, m2.RuleID)
	}
	if len(m1.CWE) != len(m2.CWE) {
		t.Errorf("CWE length mismatch: %d vs %d", len(m1.CWE), len(m2.CWE))
	}
}

// ---------------------------------------------------------------------
// All entries validation
// ---------------------------------------------------------------------

func TestGetRuleMetadata_AllHaveRemediation(t *testing.T) {
	all := AllRuleMetadata()
	if len(all) == 0 {
		t.Fatal("expected non-empty metadata map")
	}
	for id, m := range all {
		if m.Remediation == "" {
			t.Errorf("rule %s has empty Remediation", id)
		}
	}
}

func TestGetRuleMetadata_OWASPMapping(t *testing.T) {
	all := AllRuleMetadata()

	// Verify all 10 OWASP LLM Top 10 entries are mapped.
	owaspFound := make(map[string]bool)
	for _, m := range all {
		if m.OWASPLLMTop != "" {
			owaspFound[m.OWASPLLMTop] = true
		}
	}

	expectedOWASP := []string{
		"LLM01", "LLM02", "LLM03", "LLM04", "LLM05",
		"LLM06", "LLM07", "LLM08", "LLM09", "LLM10",
	}
	for _, owasp := range expectedOWASP {
		if !owaspFound[owasp] {
			t.Errorf("OWASP LLM Top 10 entry %s not found in metadata map", owasp)
		}
	}
}

func TestAllRuleMetadata_NotEmpty(t *testing.T) {
	all := AllRuleMetadata()
	if len(all) == 0 {
		t.Fatal("expected AllRuleMetadata() to return non-empty map")
	}
	// Should have at least the 10 OWASP entries plus additional patterns.
	if len(all) < 10 {
		t.Errorf("expected at least 10 entries, got %d", len(all))
	}
}

func TestRuleMetadata_CWEFormat(t *testing.T) {
	all := AllRuleMetadata()
	for id, m := range all {
		for _, cwe := range m.CWE {
			if cwe <= 0 {
				t.Errorf("rule %s has non-positive CWE ID %d", id, cwe)
			}
		}
	}
}

func TestRuleMetadata_OWASPNamesConsistent(t *testing.T) {
	// Verify that every entry with an OWASPLLMTop also has an OWASPName.
	all := AllRuleMetadata()
	for id, m := range all {
		if m.OWASPLLMTop != "" && m.OWASPName == "" {
			t.Errorf("rule %s has OWASPLLMTop '%s' but empty OWASPName", id, m.OWASPLLMTop)
		}
	}
}

func TestRuleMetadata_References(t *testing.T) {
	// Verify that all explicit OWASP entries have reference URLs.
	all := AllRuleMetadata()
	for id, m := range all {
		if m.OWASPLLMTop != "" && len(m.References) == 0 {
			t.Errorf("rule %s has OWASP mapping but no references", id)
		}
	}
}

func TestRuleMetadata_MapIsCopy(t *testing.T) {
	// AllRuleMetadata should return a copy, not the internal map.
	all := AllRuleMetadata()
	all["fake_rule"] = RuleMetadata{RuleID: "fake_rule"}

	all2 := AllRuleMetadata()
	if _, exists := all2["fake_rule"]; exists {
		t.Error("AllRuleMetadata should return a copy, not the internal map")
	}
}

func TestGetRuleMetadata_DangerousCode(t *testing.T) {
	// General dangerous_ patterns → CWE 78 (OS Command Injection)
	m := GetRuleMetadata("dangerous_js_eval")
	if m.RuleID == "" {
		t.Fatal("expected metadata for dangerous_js_eval, got empty")
	}
	if len(m.CWE) == 0 || m.CWE[0] != 78 {
		t.Errorf("expected CWE 78 for dangerous code (general), got %v", m.CWE)
	}
}

func TestGetRuleMetadata_DangerousSSRF(t *testing.T) {
	// dangerous_*endpoint* → CWE 918 (SSRF)
	rules := []string{
		"dangerous_aws_endpoint",
		"dangerous_gcp_endpoint",
	}
	for _, r := range rules {
		m := GetRuleMetadata(r)
		if m.RuleID == "" {
			t.Errorf("expected metadata for %s, got empty", r)
			continue
		}
		if len(m.CWE) == 0 || m.CWE[0] != 918 {
			t.Errorf("expected CWE 918 (SSRF) for %s, got %v", r, m.CWE)
		}
	}
}

func TestGetRuleMetadata_DangerousBase64(t *testing.T) {
	// dangerous_*b64* / dangerous_base64* → CWE 94 (Code Injection)
	rules := []string{
		"dangerous_b64_env_var",
		"dangerous_b64_eval_chain",
		"dangerous_base64_blob",
	}
	for _, r := range rules {
		m := GetRuleMetadata(r)
		if m.RuleID == "" {
			t.Errorf("expected metadata for %s, got empty", r)
			continue
		}
		if len(m.CWE) == 0 || m.CWE[0] != 94 {
			t.Errorf("expected CWE 94 (Code Injection) for %s, got %v", r, m.CWE)
		}
	}
}

func TestGetRuleMetadata_AllOWASPEntriesHaveCWE(t *testing.T) {
	// Verify that each OWASP LLM Top 10 has the correct CWE per the spec.
	all := AllRuleMetadata()
	expectedCWE := map[string]int{
		"LLM01": 77,
		"LLM02": 20,
		"LLM03": 506,
		"LLM04": 770,
		"LLM05": 829,
		"LLM06": 200,
		"LLM07": 1117,
		"LLM08": 250,
		"LLM09": 710,
		"LLM10": 1242,
	}

	// Find at least one entry per OWASP ID and check its CWE.
	owaspCWEChecked := make(map[string]bool)
	for _, m := range all {
		if m.OWASPLLMTop == "" {
			continue
		}
		if owaspCWEChecked[m.OWASPLLMTop] {
			continue
		}
		expected, ok := expectedCWE[m.OWASPLLMTop]
		if !ok {
			t.Errorf("unexpected OWASP ID %s", m.OWASPLLMTop)
			continue
		}
		if len(m.CWE) == 0 {
			t.Errorf("OWASP %s entry has no CWE", m.OWASPLLMTop)
			continue
		}
		// At least one CWE should match the expected value.
		found := false
		for _, c := range m.CWE {
			if c == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("OWASP %s expected CWE %d, got %v", m.OWASPLLMTop, expected, m.CWE)
		}
		owaspCWEChecked[m.OWASPLLMTop] = true
	}

	// Ensure all 10 were checked.
	for owasp := range expectedCWE {
		if !owaspCWEChecked[owasp] {
			t.Errorf("OWASP %s was not found in any metadata entry", owasp)
		}
	}
}
