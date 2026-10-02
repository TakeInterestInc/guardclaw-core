// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// OutputCheckResult represents the outcome of an output consistency check.
type OutputCheckResult struct {
	Consistent  bool            `json:"consistent"`
	Findings    []OutputFinding `json:"findings,omitempty"`
	ActualHash  string          `json:"actual_hash"`
	ClaimedHash string          `json:"claimed_hash,omitempty"`
}

// OutputFinding represents a single output consistency violation.
type OutputFinding struct {
	Type        OutputFindingType `json:"type"`
	Severity    string            `json:"severity"` // "critical", "high", "medium", "low"
	Description string            `json:"description"`
	Evidence    string            `json:"evidence,omitempty"`
}

// OutputFindingType categorizes output consistency violations.
type OutputFindingType string

const (
	// FindingHashMismatch indicates the output hash doesn't match the actual content.
	FindingHashMismatch OutputFindingType = "hash_mismatch"

	// FindingFabricatedContent indicates the agent output contains content not
	// present in the actual tool output.
	FindingFabricatedContent OutputFindingType = "fabricated_content"

	// FindingTruncatedOutput indicates the agent omitted significant parts of
	// the actual output.
	FindingTruncatedOutput OutputFindingType = "truncated_output"

	// FindingInventedResult indicates the agent produced results that look like
	// tool output but don't match any actual execution.
	FindingInventedResult OutputFindingType = "invented_result"

	// FindingManipulatedOutput indicates the agent altered key facts in the output
	// (numbers, paths, status codes).
	FindingManipulatedOutput OutputFindingType = "manipulated_output"
)

// fabricationPattern detects fabricated-looking content in agent output.
type fabricationPattern struct {
	name    string
	pattern *regexp.Regexp
}

// Compiled patterns for detecting output manipulation.
var outputPatterns = []fabricationPattern{
	{name: "fake_success", pattern: regexp.MustCompile(`(?i)(command\s+)?completed?\s+successfully\s*[.!]?\s*$`)},
	{name: "fake_no_error", pattern: regexp.MustCompile(`(?i)no\s+(errors?|issues?|problems?|vulnerabilities?)\s+(found|detected|discovered)`)},
	{name: "fake_exit_code", pattern: regexp.MustCompile(`exit\s+code:?\s*0\s*$`)},
	{name: "invented_path", pattern: regexp.MustCompile(`(?i)(file|path|directory)\s+(exists?|created|found|written)\s*:?\s+\S+`)},
	{name: "fabricated_count", pattern: regexp.MustCompile(`(?i)\b\d+\s+(tests?|checks?|files?|items?)\s+passed`)},
	{name: "invented_version", pattern: regexp.MustCompile(`(?i)version\s+\d+\.\d+\.\d+\s+(installed|updated|available)`)},
	{name: "fake_http_status", pattern: regexp.MustCompile(`(?i)(status|response|http)\s*:?\s*(200|201|ok|success)`)},
}

// OutputConsistencyChecker compares agent-reported results against actual tool
// outputs to detect fabrication, manipulation, or hallucination.
type OutputConsistencyChecker struct {
	// maxClaimedLen is the maximum agent claim length to analyze.
	maxClaimedLen int
}

// NewOutputConsistencyChecker creates a new checker.
func NewOutputConsistencyChecker() *OutputConsistencyChecker {
	return &OutputConsistencyChecker{
		maxClaimedLen: 64 * 1024, // 64KB
	}
}

// Check compares the agent's claimed output against the actual tool output.
// actualOutput is the raw output from the tool execution.
// claimedOutput is what the agent reports to the user.
func (c *OutputConsistencyChecker) Check(actualOutput, claimedOutput string) OutputCheckResult {
	result := OutputCheckResult{
		Consistent: true,
		ActualHash: hashContent(actualOutput),
	}

	if claimedOutput == "" || actualOutput == "" {
		return result
	}

	// Truncate excessively long claims for analysis.
	claimed := claimedOutput
	if len(claimed) > c.maxClaimedLen {
		claimed = claimed[:c.maxClaimedLen]
	}

	// 1. Hash comparison: detect any content change.
	claimedHash := hashContent(claimed)
	result.ClaimedHash = claimedHash
	if claimedHash != result.ActualHash && claimed != actualOutput {
		// Content differs — investigate further.
		c.checkFabrication(actualOutput, claimed, &result)
		c.checkTruncation(actualOutput, claimed, &result)
		c.checkManipulation(actualOutput, claimed, &result)
	}

	return result
}

// CheckWithHash verifies the agent's claimed output hash matches the actual output.
func (c *OutputConsistencyChecker) CheckWithHash(actualOutput, claimedHash string) OutputCheckResult {
	actualHash := hashContent(actualOutput)
	result := OutputCheckResult{
		Consistent:  actualHash == claimedHash,
		ActualHash:  actualHash,
		ClaimedHash: claimedHash,
	}

	if !result.Consistent {
		result.Findings = append(result.Findings, OutputFinding{
			Type:        FindingHashMismatch,
			Severity:    "critical",
			Description: "Output hash mismatch: agent's claimed hash does not match actual tool output",
			Evidence:    fmt.Sprintf("actual=%s claimed=%s", actualHash[:16], claimedHash[:min(16, len(claimedHash))]),
		})
	}

	return result
}

// checkFabrication detects content in the claimed output that doesn't appear
// in the actual output — potential fabrication.
func (c *OutputConsistencyChecker) checkFabrication(actual, claimed string, result *OutputCheckResult) {
	// Split claimed into significant lines and check each against actual.
	claimedLines := strings.Split(claimed, "\n")
	actualLower := strings.ToLower(actual)
	fabricatedCount := 0

	for _, line := range claimedLines {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) < 10 {
			continue // Skip short/empty lines.
		}

		// Check if this line or its core content appears in actual output.
		if !strings.Contains(actualLower, strings.ToLower(trimmed)) {
			// Check against fabrication patterns.
			for _, fp := range outputPatterns {
				if fp.pattern.MatchString(trimmed) {
					fabricatedCount++
					break
				}
			}
		}
	}

	if fabricatedCount > 0 {
		result.Consistent = false
		result.Findings = append(result.Findings, OutputFinding{
			Type:     FindingFabricatedContent,
			Severity: severityForFabricationCount(fabricatedCount),
			Description: fmt.Sprintf(
				"Agent output contains %d lines matching fabrication patterns not found in actual tool output",
				fabricatedCount,
			),
		})
	}
}

// checkTruncation detects when the agent omits large portions of the actual output.
func (c *OutputConsistencyChecker) checkTruncation(actual, claimed string, result *OutputCheckResult) {
	actualLen := len(actual)
	claimedLen := len(claimed)

	if actualLen == 0 {
		return
	}

	// Flag when claimed output is less than 20% of actual and actual is substantial.
	ratio := float64(claimedLen) / float64(actualLen)
	if ratio < 0.2 && actualLen > 200 {
		result.Consistent = false
		result.Findings = append(result.Findings, OutputFinding{
			Type:     FindingTruncatedOutput,
			Severity: "medium",
			Description: fmt.Sprintf(
				"Agent output is %.0f%% of actual output (%d vs %d bytes) — significant content omitted",
				ratio*100, claimedLen, actualLen,
			),
		})
	}
}

// checkManipulation detects when the agent alters key facts: numbers, paths,
// status codes, or error messages.
func (c *OutputConsistencyChecker) checkManipulation(actual, claimed string, result *OutputCheckResult) {
	// Extract key facts from actual output.
	actualFacts := extractKeyFacts(actual)
	claimedFacts := extractKeyFacts(claimed)

	// Find facts in claimed that contradict actual.
	contradictions := 0
	for key, claimedVal := range claimedFacts {
		if actualVal, ok := actualFacts[key]; ok {
			if claimedVal != actualVal {
				contradictions++
			}
		}
	}

	if contradictions > 0 {
		result.Consistent = false
		result.Findings = append(result.Findings, OutputFinding{
			Type:     FindingManipulatedOutput,
			Severity: "high",
			Description: fmt.Sprintf(
				"Agent output contradicts %d key facts from actual tool output (numbers, status codes, or paths altered)",
				contradictions,
			),
		})
	}
}

// Key fact extraction patterns.
var (
	exitCodePattern = regexp.MustCompile(`(?i)exit\s+code:?\s*(\d+)`)
	httpCodePattern = regexp.MustCompile(`(?i)(?:status|http)[:\s]+(\d{3})`)
	countPattern    = regexp.MustCompile(`(?i)(\d+)\s+(?:tests?|errors?|warnings?|files?|passed|failed)`)
)

// extractKeyFacts pulls out verifiable facts (exit codes, HTTP status, counts).
func extractKeyFacts(text string) map[string]string {
	facts := make(map[string]string)

	if m := exitCodePattern.FindStringSubmatch(text); len(m) > 1 {
		facts["exit_code"] = m[1]
	}
	if m := httpCodePattern.FindStringSubmatch(text); len(m) > 1 {
		facts["http_status"] = m[1]
	}
	// Extract all count facts.
	for i, m := range countPattern.FindAllStringSubmatch(text, 5) {
		facts[fmt.Sprintf("count_%d", i)] = m[1]
	}

	return facts
}

// hashContent computes a SHA-256 hex digest of the given content.
func hashContent(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func severityForFabricationCount(count int) string {
	switch {
	case count >= 5:
		return "critical"
	case count >= 3:
		return "high"
	default:
		return "medium"
	}
}
