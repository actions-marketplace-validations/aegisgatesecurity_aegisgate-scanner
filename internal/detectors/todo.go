// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Scanner — Technical Debt Marker Detection Patterns
// =========================================================================
//
// Detects TODO, FIXME, HACK, XXX, BUG, and NOTE comments that often
// indicate security debt, incomplete implementations, or known issues
// in AI artifact source code (agent skills, training pipelines, etc.).
//
// These markers are standard in software engineering and serve as early
// warning indicators for:
//   - Incomplete security controls (FIXME)
//   - Known workarounds with risks (HACK)
//   - Critical unresolved issues (XXX, BUG)
//   - Planned but unimplemented features (TODO)
//
// Severity is assigned based on marker type:
//   BUG/FIXME → HIGH (known broken code)
//   HACK/XXX  → MEDIUM (risky workaround or critical warning)
//   TODO/NOTE → LOW (informational, planned work)
//
// =========================================================================

package detectors

// TodoPatterns defines technical debt marker detection patterns.
var TodoPatterns = []PatternDef{
	// --- BUG — known broken code (HIGH) ---
	{
		Name:        "todo_bug",
		Severity:    SeverityHigh,
		Regex:       `(?i)\bBUG\b[:\s]`,
		Description: "BUG comment — known broken or incorrect code",
	},
	{
		Name:        "todo_fixme",
		Severity:    SeverityHigh,
		Regex:       `(?i)\bFIXME\b[:\s]`,
		Description: "FIXME comment — known issue requiring fix",
	},

	// --- HACK/XXX — risky workarounds or critical warnings (MEDIUM) ---
	{
		Name:        "todo_hack",
		Severity:    SeverityMedium,
		Regex:       `(?i)\bHACK\b[:\s]`,
		Description: "HACK comment — risky workaround or non-standard approach",
	},
	{
		Name:        "todo_xxx",
		Severity:    SeverityMedium,
		Regex:       `\bXXX\b[:\s]`,
		Description: "XXX comment — critical warning or unresolved concern",
	},

	// --- TODO/NOTE — planned work (LOW) ---
	{
		Name:        "todo_todo",
		Severity:    SeverityLow,
		Regex:       `(?i)\bTODO\b[:\s(]`,
		Description: "TODO comment — planned but unimplemented work",
	},
	{
		Name:        "todo_note",
		Severity:    SeverityLow,
		Regex:       `(?i)\bNOTE\b[:\s]`,
		Description: "NOTE comment — informational marker for reviewers",
	},

	// --- Security-specific debt markers ---
	{
		Name:        "todo_security",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:TODO|FIXME|HACK|XXX|BUG)\b[:\s]*(?:security|auth|crypto|encrypt|vulnerab|insecure|unsafe|password|secret|key|token|sanitize|validate|escape|inject|xss|csrf|sql|rbac|permission|privilege)`,
		Description: "Technical debt marker referencing security — indicates known security gap",
	},
	{
		Name:        "todo_not_implemented",
		Severity:    SeverityMedium,
		Regex:       `(?i)\b(?:TODO|FIXME)\b[:\s]*(?:not\s+implemented|unimplemented|placeholder|stub|mock|dummy|temp(?:orary)?|remove\s+(?:this|later))`,
		Description: "Technical debt marker indicating unimplemented or placeholder code",
	},
}

// CompiledTodoPatterns holds pre-compiled technical debt marker patterns.
var CompiledTodoPatterns []compiledPattern

func init() {
	CompiledTodoPatterns = compilePatterns(TodoPatterns)
}

// DetectTodo scans text for technical debt markers and returns matches.
func DetectTodo(text string) []Match {
	return detectWithPatterns(text, CompiledTodoPatterns, string(CategoryTodo))
}
