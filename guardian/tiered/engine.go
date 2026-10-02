// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package tiered

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TakeInterestInc/guardclaw-core/guardian/security"
)

// Engine is the tiered detection pipeline integrating Bloom, AC, RE2, Entropy,
// and Resource Accounting. Constructed once at daemon startup and reused for
// all scan requests. Thread-safe for concurrent Scan() calls.
type Engine struct {
	mu       sync.RWMutex
	bloom    *BloomFilter
	ac       *ACMatcher
	re2      *CompositeRE2
	entropy  *EntropyAnalyzer
	resource *ResourceAccountant
	ready    bool
	// selfProtect holds the self-protection patterns present in the pattern
	// set, keyed by name. security.MatchSelfProtection runs alongside Tier 3
	// only for names in this map, so an engine built from a custom pattern
	// set without them behaves as before.
	selfProtect map[string]security.ExportedPattern

	// Atomic counters for stats.
	totalScans    atomic.Int64
	denyCount     atomic.Int64
	escalateCount atomic.Int64
	allowCount    atomic.Int64
}

// EngineConfig controls engine initialization parameters.
// All zero values use sensible defaults.
type EngineConfig struct {
	BloomCapacity    int                        // expected Bloom entries (default 1M)
	BloomFPRate      float64                    // Bloom FP rate (default 0.000001)
	Patterns         []security.ExportedPattern // nil = use ExportAllPatterns()
	MaxGroupSize     int                        // RE2 composite group size (default 40)
	EntropyThreshold float64                    // bits per byte (default 4.5)
	MemoryBudget     uint64                     // bytes (default 65 MB)
}

// ScanResult is the decision output from the tiered detection engine.
type ScanResult struct {
	Decision        string         `json:"decision"`         // "allow", "deny", "escalate"
	PatternID       string         `json:"pattern_id"`       // e.g. "GC-CMD-042"; empty if allow
	Reason          string         `json:"reason"`           // human-readable explanation
	Severity        string         `json:"severity"`         // "critical", "high", "medium", "low", "info"
	Score           float64        `json:"score"`            // 0.0-1.0 confidence
	LatencyUS       int64          `json:"latency_us"`       // scan latency in microseconds
	MatchedPatterns []string       `json:"matched_patterns"` // all pattern IDs that matched
	Tier            int            `json:"tier"`             // 1-4 (tier that produced decision); 0 if allow
	ResourceStatus  ResourceStatus `json:"resource_status"`  // memory health metadata
}

// EngineStats holds aggregate engine metrics.
type EngineStats struct {
	BloomEntries  uint64
	ACPatterns    int
	RE2Groups     int
	RE2Patterns   int
	TotalScans    int64
	DenyCount     int64
	EscalateCount int64
	AllowCount    int64
}

// NewEngine constructs a fully initialized tiered detection engine.
// If cfg is nil, uses all defaults. If any tier fails to initialize,
// the engine enters fallback mode (Ready()==false, all scans return "allow").
func NewEngine(cfg *EngineConfig) (*Engine, error) {
	if cfg == nil {
		cfg = &EngineConfig{}
	}

	// Apply defaults.
	patterns := cfg.Patterns
	if patterns == nil {
		patterns = security.ExportAllPatterns()
	}
	bloomCap := cfg.BloomCapacity
	if bloomCap <= 0 {
		bloomCap = 1_000_000
	}
	bloomFP := cfg.BloomFPRate
	if bloomFP <= 0 {
		bloomFP = 0.000001
	}
	maxGroup := cfg.MaxGroupSize
	if maxGroup <= 0 {
		maxGroup = DefaultMaxGroupSize
	}
	memBudget := cfg.MemoryBudget
	if memBudget == 0 {
		memBudget = DefaultMemoryBudget
	}

	e := &Engine{}

	// Tier 1: Bloom filter — seeded with hashes of known-bad pattern strings.
	bf, err := NewBloomFilter(bloomCap, bloomFP)
	if err != nil {
		slog.Error("engine: bloom filter init failed", "error", err)
		return nil, fmt.Errorf("engine: bloom filter init failed: %w", err)
	}
	seedBloomFromPatterns(bf, patterns)
	e.bloom = bf

	// Tier 2: Aho-Corasick from exported pattern literals.
	acPatterns := extractACPatterns(patterns)
	if len(acPatterns) > 0 {
		ac, err := NewACMatcher(acPatterns)
		if err != nil {
			slog.Error("engine: AC matcher init failed", "error", err)
			return nil, fmt.Errorf("engine: AC matcher init failed: %w", err)
		}
		e.ac = ac
	}

	// Tier 3: Composite RE2.
	e.re2 = NewCompositeRE2(patterns, maxGroup)
	e.selfProtect = selfProtectPatterns(patterns)

	// Tier 4: Entropy analyzer.
	ea := NewEntropyAnalyzer()
	if cfg.EntropyThreshold > 0 {
		ea = ea.WithThreshold(cfg.EntropyThreshold)
	}
	e.entropy = ea

	// Resource accounting.
	ra := NewResourceAccountant()
	if memBudget != DefaultMemoryBudget {
		ra = ra.WithBudget(memBudget)
	}
	e.resource = ra

	e.ready = true
	return e, nil
}

// seedBloomFromPatterns inserts SHA-256 hashes of pattern regex strings into
// the Bloom filter. This gives Tier 1 a fast O(1) pre-check: if an input's
// hash matches a known pattern string exactly, it's an immediate deny.
// The Bloom filter also accepts IOC-style exact matches (domains, IPs, paths).
func seedBloomFromPatterns(bf *BloomFilter, patterns []security.ExportedPattern) {
	for _, p := range patterns {
		hash := sha256.Sum256([]byte(p.Pattern))
		bf.Insert(hash[:])
	}
	// Seed with curated known-bad exact strings (IOC-style).
	// These are inputs that should trigger an immediate Bloom hit.
	knownBad := []string{
		"169.254.169.254",
		"metadata.google.internal",
		"metadata.google.internal/computeMetadata/v1/",
		"100.100.100.200",       // Alibaba Cloud metadata
		"fd00:ec2::254",         // AWS IPv6 metadata
		"instance-data/latest/", // DigitalOcean metadata
	}
	for _, s := range knownBad {
		hash := sha256.Sum256([]byte(s))
		bf.Insert(hash[:])
	}
}

// extractACPatterns extracts unique literal substrings suitable for AC matching
// from exported patterns. Combines a curated keyword list with literals extracted
// from pattern strings that contain no regex metacharacters.
func extractACPatterns(patterns []security.ExportedPattern) []string {
	if len(patterns) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var result []string

	// Curated high-confidence literals for fast AC scanning.
	keywords := []string{
		"ignore previous instructions",
		"ignore all previous instructions",
		"disregard previous instructions",
		"forget your instructions",
		"override your instructions",
		"you are now",
		"act as if",
		"pretend you are",
		"reveal your prompt",
		"/etc/passwd",
		"/etc/shadow",
		".ssh/id_rsa",
		".aws/credentials",
		"curl http://evil",
		"wget http://evil",
		"nc evil.com",
		"<script>",
		"</script>",
		"DROP TABLE",
		"UNION SELECT",
		"OR 1=1",
		"127.0.0.1",
		"169.254.169.254",
		"metadata.google.internal",
		"0x7f000001",
		"localhost:2375",
	}
	for _, kw := range keywords {
		if !seen[kw] {
			seen[kw] = true
			result = append(result, kw)
		}
	}

	// Extract literal patterns (no regex metacharacters) from exported patterns.
	// A pattern is "literal" if it contains none of: . * + ? [ ] ( ) { } | ^ $ \.
	for _, p := range patterns {
		pat := p.Pattern
		if len(pat) < 4 || len(pat) > 200 {
			continue // Skip very short or very long patterns.
		}
		if isLiteralPattern(pat) && !seen[pat] {
			seen[pat] = true
			result = append(result, pat)
		}
	}

	return result
}

// isLiteralPattern returns true if s contains no regex metacharacters,
// meaning it can be used as a literal Aho-Corasick keyword.
func isLiteralPattern(s string) bool {
	for _, c := range s {
		switch c {
		case '.', '*', '+', '?', '[', ']', '(', ')', '{', '}', '|', '^', '$', '\\':
			return false
		}
	}
	return true
}

// Scan runs input through all tiers with short-circuit semantics.
// Thread-safe: multiple goroutines may call Scan() concurrently.
func (e *Engine) Scan(input string) ScanResult {
	start := time.Now()
	result := ScanResult{Decision: "allow"}

	e.totalScans.Add(1)

	if !e.ready {
		slog.Error("engine not ready, denying all requests")
		result.Decision = "deny"
		result.Reason = "detection engine not initialized"
		result.Severity = "critical"
		result.LatencyUS = time.Since(start).Microseconds()
		e.denyCount.Add(1)
		return result
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	if input == "" {
		result.LatencyUS = time.Since(start).Microseconds()
		result.ResourceStatus = e.resource.Check()
		e.allowCount.Add(1)
		return result
	}

	// Normalize once for the pattern-matching tiers (AC + RE2). NormalizeInput
	// applies NFKC, confusable/homoglyph folding, zero-width stripping, math-symbol
	// and fullwidth ASCII mapping, and HTML-concealment removal — without this,
	// unicode-evasion attacks (𝐢𝐠𝐧𝐨𝐫𝐞, fullwidth ｅｖｉｌ, zero-width splits) bypass
	// every pattern. Bloom (exact hash) and entropy (measures the raw bytes) use
	// the original input.
	normalized := security.NormalizeInput(input)

	// Tier 1: Bloom filter (hash lookup).
	hash := sha256.Sum256([]byte(input))
	if e.bloom.Lookup(hash[:]) {
		result.Decision = "deny"
		result.Tier = 1
		result.Severity = "critical"
		result.Score = 1.0
		result.Reason = "Input hash matches known-malicious indicator"
		result.PatternID = "GC-BLOOM-HIT"
		result.MatchedPatterns = []string{"GC-BLOOM-HIT"}
		result.LatencyUS = time.Since(start).Microseconds()
		result.ResourceStatus = e.resource.Check()
		e.denyCount.Add(1)
		return result
	}

	// Tier 2: Aho-Corasick (literal scan).
	if e.ac != nil {
		if match := e.ac.ScanFirst(normalized); match != nil {
			result.Decision = "deny"
			result.Tier = 2
			result.Severity = "high"
			result.Score = 0.9
			result.Reason = fmt.Sprintf("Literal match: %q", match.Pattern)
			result.PatternID = fmt.Sprintf("GC-AC-%04d", match.PatternID)
			result.MatchedPatterns = []string{result.PatternID}
			result.LatencyUS = time.Since(start).Microseconds()
			result.ResourceStatus = e.resource.Check()
			e.denyCount.Add(1)
			return result
		}
	}

	// Tier 3: Composite RE2 (regex scan).
	matches := e.re2.Scan(normalized)
	if len(e.selfProtect) > 0 {
		if name, ok := security.MatchSelfProtection(normalized); ok {
			p, known := e.selfProtect[name]
			seen := false
			for _, m := range matches {
				if m.PatternID == name {
					seen = true
				}
			}
			if known && !seen {
				matches = append(matches, CompositeMatch{
					PatternID: name, Domain: p.Domain, Category: p.Category,
					Severity: p.Severity, Confidence: p.Confidence, GroupID: -1,
				})
			}
		}
	}
	if len(matches) > 0 {
		best := matches[0]
		for _, m := range matches[1:] {
			if m.Severity > best.Severity {
				best = m
			}
		}
		// Decision: deny by default. But the "delimiter marker" class (chat-template
		// tokens like <|im_start|>, <system> tags) is a strong injection SIGNAL that
		// also appears in legitimate text documenting those tokens. Such a marker is
		// never silently allowed — it routes to ESCALATE (human/second-check) — UNLESS
		// some other, unambiguous attack pattern also fired, in which case deny wins.
		decision := "escalate"
		for _, m := range matches {
			if !escalateOnlyPatterns[m.PatternID] && !escalateOnlyDomains[m.Domain] {
				decision = "deny"
				break
			}
		}
		result.Decision = decision
		result.Tier = 3
		result.Score = best.Confidence
		result.PatternID = best.PatternID
		result.Reason = fmt.Sprintf("Pattern match in %s: %s", best.Domain, best.PatternID)
		result.Severity = severityFromScore(best.Severity)
		result.MatchedPatterns = make([]string, len(matches))
		for i, m := range matches {
			result.MatchedPatterns[i] = m.PatternID
		}
		result.LatencyUS = time.Since(start).Microseconds()
		result.ResourceStatus = e.resource.Check()
		if decision == "deny" {
			e.denyCount.Add(1)
		} else {
			e.escalateCount.Add(1)
		}
		return result
	}

	// Tier 4: Entropy analysis.
	er := e.entropy.Analyze(input)
	if er.Flagged {
		result.Decision = "escalate"
		result.Tier = 4
		result.Score = er.MaxEntropy / 8.0
		result.Severity = "medium"
		result.Reason = fmt.Sprintf("High entropy detected: %.2f bits/byte at offset %d", er.MaxEntropy, er.Offset)
		result.PatternID = "GC-ENTROPY-HIGH"
		result.MatchedPatterns = []string{"GC-ENTROPY-HIGH"}
		result.LatencyUS = time.Since(start).Microseconds()
		result.ResourceStatus = e.resource.Check()
		e.escalateCount.Add(1)
		return result
	}

	// All tiers passed — allow.
	result.ResourceStatus = e.resource.Check()
	result.LatencyUS = time.Since(start).Microseconds()
	e.allowCount.Add(1)
	return result
}

// Rebuild replaces AC and RE2 patterns with a new pattern set.
// NOTE: Bloom filter is NOT rebuilt — it retains its original hashes.
// Thread-safe: acquires write lock, blocks concurrent Scan() calls during rebuild.
func (e *Engine) Rebuild(patterns []security.ExportedPattern) {
	e.mu.Lock()
	defer e.mu.Unlock()

	acPatterns := extractACPatterns(patterns)
	if len(acPatterns) > 0 {
		ac, err := NewACMatcher(acPatterns)
		if err != nil {
			slog.Error("engine: rebuild AC failed", "error", err)
		} else {
			e.ac = ac
		}
	}
	e.re2.Rebuild(patterns)
	e.selfProtect = selfProtectPatterns(patterns)
}

// selfProtectPatterns returns the self-protection patterns in a pattern set.
func selfProtectPatterns(patterns []security.ExportedPattern) map[string]security.ExportedPattern {
	names := map[string]bool{}
	for _, n := range security.SelfProtectionPatternNames() {
		names[n] = true
	}
	out := map[string]security.ExportedPattern{}
	for _, p := range patterns {
		if names[p.Name] {
			out[p.Name] = p
		}
	}
	return out
}

// Ready returns true if all tiers initialized successfully.
func (e *Engine) Ready() bool {
	return e.ready
}

// Stats returns aggregate engine metrics.
func (e *Engine) Stats() EngineStats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	stats := EngineStats{
		BloomEntries:  e.bloom.Len(),
		RE2Groups:     e.re2.GroupCount(),
		RE2Patterns:   e.re2.PatternCount(),
		TotalScans:    e.totalScans.Load(),
		DenyCount:     e.denyCount.Load(),
		EscalateCount: e.escalateCount.Load(),
		AllowCount:    e.allowCount.Load(),
	}
	if e.ac != nil {
		stats.ACPatterns = e.ac.PatternCount()
	}
	return stats
}

// severityFromScore converts a 0.0-1.0 score to a severity string.
func severityFromScore(score float64) string {
	switch {
	case score >= 0.9:
		return "critical"
	case score >= 0.7:
		return "high"
	case score >= 0.4:
		return "medium"
	case score >= 0.1:
		return "low"
	default:
		return "info"
	}
}
