// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

// ExportedPattern is a serializable representation of a compiled pattern
// for seeding to Firestore or other external stores.
type ExportedPattern struct {
	Name       string  `json:"name"`
	Pattern    string  `json:"pattern"`
	Category   string  `json:"category"`
	Domain     string  `json:"domain"` // e.g. "prompt_injection", "command_injection", "xss"
	Severity   float64 `json:"severity"`
	Confidence float64 `json:"confidence"`
}

// ExportAllPatterns returns every compiled pattern in a flat, serializable slice.
// This is used by the seed-patterns endpoint to populate Firestore base_patterns.
func ExportAllPatterns() []ExportedPattern {
	var out []ExportedPattern

	for _, p := range PromptInjectionPatterns {
		out = append(out, ExportedPattern{
			Name:       p.Name,
			Pattern:    p.Pattern.String(),
			Category:   string(p.Category),
			Domain:     "prompt_injection",
			Severity:   p.Severity,
			Confidence: p.Confidence,
		})
	}

	for _, p := range CommandInjectionPatterns {
		out = append(out, ExportedPattern{
			Name:       p.Name,
			Pattern:    p.Pattern.String(),
			Category:   string(p.Category),
			Domain:     "command_injection",
			Severity:   p.Severity,
			Confidence: p.Confidence,
		})
	}

	for _, p := range SQLInjectionPatterns {
		out = append(out, ExportedPattern{
			Name:       p.Name,
			Pattern:    p.Pattern.String(),
			Category:   string(p.Category),
			Domain:     "sql_injection",
			Severity:   p.Severity,
			Confidence: p.Confidence,
		})
	}

	for _, p := range XSSPatterns {
		out = append(out, ExportedPattern{
			Name:       p.Name,
			Pattern:    p.Pattern.String(),
			Category:   string(p.Category),
			Domain:     "xss",
			Severity:   p.Severity,
			Confidence: p.Confidence,
		})
	}

	for _, p := range SSRFPatterns {
		out = append(out, ExportedPattern{
			Name:       p.Name,
			Pattern:    p.Pattern.String(),
			Category:   string(p.Category),
			Domain:     "ssrf",
			Severity:   p.Severity,
			Confidence: p.Confidence,
		})
	}

	for _, p := range PathTraversalPatterns {
		out = append(out, ExportedPattern{
			Name:       p.Name,
			Pattern:    p.Pattern.String(),
			Category:   string(p.Category),
			Domain:     "path_traversal",
			Severity:   p.Severity,
			Confidence: p.Confidence,
		})
	}

	for _, p := range HeaderInjectionPatterns {
		out = append(out, ExportedPattern{
			Name:       p.Name,
			Pattern:    p.Pattern.String(),
			Category:   string(p.Category),
			Domain:     "header_injection",
			Severity:   p.Severity,
			Confidence: p.Confidence,
		})
	}

	for _, p := range BlockedToolPatterns {
		out = append(out, ExportedPattern{
			Name:       p.Name,
			Pattern:    p.Pattern.String(),
			Category:   string(p.Category),
			Domain:     "blocked_tools",
			Severity:   p.Severity,
			Confidence: 1.0, // BlockedToolPattern has no Confidence field; tools are deterministic
		})
	}

	// Net-new generated patterns (model-assisted, adversarially reviewed,
	// compile-validated, corpus-gated). See guardian/security/generated_patterns.go.
	out = append(out, GeneratedPatterns...)

	// PII detection patterns (71 types)
	out = append(out, NewPIIDetector().ExportPatterns()...)

	// URL exfiltration service patterns (15 services)
	out = append(out, NewURLValidator().ExportPatterns()...)

	// NOTE: no threat-intelligence feed is seeded here. ExportAllPatterns()
	// returns only the static, in-package pattern set. A caller that has its own
	// patterns can add them with tiered.Engine.Rebuild([]ExportedPattern).

	return out
}
