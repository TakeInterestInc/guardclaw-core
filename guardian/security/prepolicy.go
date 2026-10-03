// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"fmt"
	"strings"
)

// PIIMode controls optional PII/secrets scanning behavior before policy evaluation.
type PIIMode string

const (
	PIIModeOff     PIIMode = "off"
	PIIModeMonitor PIIMode = "monitor"
	PIIModeRedact  PIIMode = "redact"
)

// ParsePIIMode normalizes a PII mode string. The default (empty string) is
// PIIModeRedact to ensure PII is never leaked without explicit opt-out.
func ParsePIIMode(raw string) PIIMode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(PIIModeOff):
		return PIIModeOff
	case string(PIIModeMonitor):
		return PIIModeMonitor
	default:
		return PIIModeRedact
	}
}

// PrePolicyConfig configures pre-policy validation behavior.
type PrePolicyConfig struct {
	PIIMode      PIIMode
	URLExfilMode string // "block" (default), "monitor", or "off"
}

// PrePolicyResult contains normalized validation outputs.
type PrePolicyResult struct {
	Injection       *InjectionCheckResult
	PIIMatches      []PIIMatch
	SanitizedMap    map[string]any
	URLExfilBlocked bool
	URLExfilReason  string
}

// ValidatePrePolicyInput runs shared pre-policy checks used by HTTP and MCP paths.
func ValidatePrePolicyInput(input map[string]any, cfg PrePolicyConfig) *PrePolicyResult {
	result := &PrePolicyResult{}
	if input == nil {
		return result
	}

	// Prompt injection detection is mandatory on pre-policy paths.
	injection := CheckInputMap(input)
	if injection.Detected {
		result.Injection = injection
		return result
	}

	// URL exfiltration check (default: block).
	exfilMode := cfg.URLExfilMode
	if exfilMode == "" {
		exfilMode = "block"
	}
	if exfilMode != "off" {
		urlValidator := NewURLValidator()
		urls := extractURLsFromMap(input)
		for _, u := range urls {
			vr := urlValidator.Validate(u)
			for _, threat := range vr.Threats {
				if threat == ThreatExfil {
					if exfilMode == "block" {
						result.URLExfilBlocked = true
						result.URLExfilReason = fmt.Sprintf("blocked exfiltration URL: %s", u)
						return result
					}
					// monitor mode: record but don't block
					result.URLExfilReason = fmt.Sprintf("exfiltration URL detected: %s", u)
					break
				}
			}
		}
	}

	mode := cfg.PIIMode
	if mode == "" {
		mode = PIIModeRedact
	}
	if mode == PIIModeOff {
		return result
	}

	detector := NewPIIDetector()
	matches := detector.DetectInMap(input)
	if len(matches) == 0 {
		return result
	}

	result.PIIMatches = matches
	if mode == PIIModeRedact {
		result.SanitizedMap = detector.RedactMap(input)
	}

	return result
}

// extractURLsFromMap recursively finds all URL strings in a map.
func extractURLsFromMap(m map[string]any) []string {
	var urls []string
	walkMapStrings(m, func(s string) {
		if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
			urls = append(urls, s)
		}
	})
	return urls
}

// walkMapStrings recursively visits JSON string leaves, including nested arrays.
func walkMapStrings(m map[string]any, fn func(string)) {
	walkValueStrings(m, fn)
}

func walkValueStrings(value any, fn func(string)) {
	switch v := value.(type) {
	case string:
		fn(v)
	case map[string]any:
		for _, item := range v {
			walkValueStrings(item, fn)
		}
	case []any:
		for _, item := range v {
			walkValueStrings(item, fn)
		}
	}
}

// mapValueStrings copies JSON containers and transforms every string leaf.
// Nonstring leaves, keys, and array order are preserved.
func mapValueStrings(value any, fn func(string) string) any {
	switch v := value.(type) {
	case string:
		return fn(v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = mapValueStrings(item, fn)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = mapValueStrings(item, fn)
		}
		return out
	default:
		return value
	}
}
