// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// EgressFinding describes a single security issue found in tool output.
type EgressFinding struct {
	Type    string `json:"type"`    // "pii", "exfil_url", "protected_path"
	Detail  string `json:"detail"`  // Human-readable description
	Blocked bool   `json:"blocked"` // True if the output was blocked entirely
}

// EgressResult holds the outcome of egress scanning.
type EgressResult struct {
	Findings []EgressFinding `json:"findings,omitempty"`
	Blocked  bool            `json:"blocked"`
	Reason   string          `json:"reason,omitempty"`
}

// HasFindings returns true if any security issues were detected.
func (r *EgressResult) HasFindings() bool {
	return len(r.Findings) > 0
}

// EgressScanner applies comprehensive output scanning: PII redaction,
// URL exfiltration detection, and protected path content blocking.
type EgressScanner struct {
	pii   *PIIDetector
	url   *URLValidator
	paths *ProtectedPathChecker
}

// EgressOption configures the EgressScanner.
type EgressOption func(*EgressScanner)

// WithProtectedPaths sets a custom protected path checker.
func WithProtectedPaths(p *ProtectedPathChecker) EgressOption {
	return func(e *EgressScanner) {
		e.paths = p
	}
}

// WithURLValidator sets a custom URL validator.
func WithURLValidator(v *URLValidator) EgressOption {
	return func(e *EgressScanner) {
		e.url = v
	}
}

// NewEgressScanner creates a scanner with full PII + URL + path checking.
func NewEgressScanner(opts ...EgressOption) *EgressScanner {
	e := &EgressScanner{
		pii:   NewPIIDetector(),
		url:   NewURLValidator(),
		paths: NewDefaultProtectedPathChecker(),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// urlPattern matches http(s) URLs in output text.
var egressURLPattern = regexp.MustCompile(`https?://[^\s"'<>\x60\x5d\x5b]+`)

// ScanString scans a string output for PII, exfil URLs, and protected paths.
// It returns the redacted string and an EgressResult. If the output references
// protected path content, the result is blocked entirely.
func (e *EgressScanner) ScanString(output string) (string, *EgressResult) {
	result := &EgressResult{}

	// 1. Redact PII first (before URL replacement to avoid false positives
	// on redaction tokens like "[EXFIL URL REDACTED]" matching SWIFT BIC).
	piiMatches := e.pii.Detect(output)
	if len(piiMatches) > 0 {
		output = e.pii.RedactString(output)
		for _, m := range piiMatches {
			result.Findings = append(result.Findings, EgressFinding{
				Type:   "pii",
				Detail: fmt.Sprintf("PII detected: %s", m.Type),
			})
		}
	}

	// 2. Check for exfil URLs in the (PII-redacted) output.
	urls := egressURLPattern.FindAllString(output, -1)
	for _, u := range urls {
		vr := e.url.Validate(u)
		for _, threat := range vr.Threats {
			if threat == ThreatExfil {
				result.Findings = append(result.Findings, EgressFinding{
					Type:   "exfil_url",
					Detail: fmt.Sprintf("Exfiltration service URL detected: %s", u),
				})
				output = strings.ReplaceAll(output, u, "[EXFIL URL REDACTED]")
				break
			}
		}
	}

	return output, result
}

// ScanAndRedact scans output text and returns the redacted version plus findings.
// This is the primary entry point for string-based tool output.
func (e *EgressScanner) ScanAndRedact(output string) (string, *EgressResult) {
	return e.ScanString(output)
}

// ScanMap scans a structured tool response, retaining PII field context and
// recursively scanning string values for PII and exfil URLs.
func (e *EgressScanner) ScanMap(output map[string]any) (map[string]any, *EgressResult) {
	result := &EgressResult{}
	redacted := e.scanMapRecursive(output, result)
	return redacted, result
}

// CheckProtectedPath returns true if the path is protected and should be blocked.
func (e *EgressScanner) CheckProtectedPath(path string) bool {
	return e.paths.IsProtected(path)
}

// scanMapRecursive walks a map and scans/redacts all string values.
func (e *EgressScanner) scanMapRecursive(input map[string]any, result *EgressResult) map[string]any {
	return e.scanValue(input, result).(map[string]any)
}

func (e *EgressScanner) scanValue(input any, result *EgressResult) any {
	return mapPIIFields(input, "", func(key string, value any) any {
		if matches := e.pii.detectField(key, value); len(matches) > 0 {
			for _, match := range matches {
				result.Findings = append(result.Findings, EgressFinding{Type: "pii", Detail: fmt.Sprintf("PII detected: %s", match.Type)})
			}
			return "[PII REDACTED]"
		}
		if s, ok := value.(string); ok {
			redacted, r := e.ScanString(s)
			result.Findings = append(result.Findings, r.Findings...)
			if r.Blocked {
				result.Blocked = true
				result.Reason = r.Reason
			}
			return redacted
		}
		return value
	})
}

// ScanJSON scans decoded JSON leaves, including root arrays and strings.
// Invalid JSON retains the plain-text scanning behavior.
func (e *EgressScanner) ScanJSON(jsonStr string) (string, *EgressResult) {
	var value any
	if err := json.Unmarshal([]byte(jsonStr), &value); err != nil {
		return e.ScanString(jsonStr)
	}
	result := &EgressResult{}
	redacted := e.scanValue(value, result)
	payload, err := json.Marshal(redacted)
	if err != nil {
		return e.ScanString(jsonStr)
	}
	return string(payload), result
}
