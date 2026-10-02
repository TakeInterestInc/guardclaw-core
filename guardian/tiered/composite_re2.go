// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package tiered

import (
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/TakeInterestInc/guardclaw-core/guardian/security"
)

// DefaultMaxGroupSize is the maximum number of sub-patterns per composite
// alternation group. At 40 patterns per group, 1,590 patterns → ~44 groups.
// Design doc §4.1 recommends 25-50; 40 is the production sweet spot.
const DefaultMaxGroupSize = 40

// CompositeMatch is the result of a composite RE2 scan.
// It carries full hit attribution: exact pattern ID, domain, severity, and
// the matched substring — enabling the "[GC-{PatternID}] {reason}" rejection
// message format described in design doc §8.4.
type CompositeMatch struct {
	PatternID  string  // unique name from ExportedPattern.Name
	Domain     string  // e.g. "prompt_injection", "command_injection"
	Category   string  // e.g. "instruction_override", "shell_metachar"
	Severity   float64 // 0.0-1.0
	Confidence float64 // 0.0-1.0
	Matched    string  // the substring that triggered the match
	GroupID    int     // which composite group fired (for diagnostics)
}

// compiledGroup is a single compiled alternation covering up to DefaultMaxGroupSize patterns.
// All patterns in a group share the same Domain, enabling fast domain-level attribution.
type compiledGroup struct {
	id       int
	compiled *regexp.Regexp
	domain   string
}

// patternEntry is a single individually-compiled pattern within a group.
// Used for hit attribution when the group alternation fires.
type patternEntry struct {
	name       string
	compiled   *regexp.Regexp
	domain     string
	category   string
	severity   float64
	confidence float64
}

// CompositeRE2 holds compiled composite regex groups with a reverse index
// for hit attribution. Thread-safe: Scan (read) and Rebuild/Add/Remove (write)
// may run concurrently across goroutines.
type CompositeRE2 struct {
	mu          sync.RWMutex
	groups      []compiledGroup            // compiled alternation groups
	reverseIdx  map[int][]patternEntry     // groupID → individual pattern entries
	maxGroupSz  int                        // max sub-patterns per group
	allPatterns []security.ExportedPattern // source of truth for Add/Remove/Rebuild
}

// NewCompositeRE2 builds composite groups from the given patterns.
// Patterns are grouped by Domain, then split into chunks of maxGroupSize.
// Invalid regexes and degenerate patterns (matching empty string) are skipped
// with a slog.Warn and do not contribute to PatternCount.
func NewCompositeRE2(patterns []security.ExportedPattern, maxGroupSize int) *CompositeRE2 {
	if maxGroupSize <= 0 {
		maxGroupSize = DefaultMaxGroupSize
	}
	if patterns == nil {
		patterns = []security.ExportedPattern{}
	}
	c := &CompositeRE2{
		maxGroupSz:  maxGroupSize,
		allPatterns: patterns,
		reverseIdx:  make(map[int][]patternEntry),
	}
	c.buildFrom(patterns)
	return c
}

// NewCompositeRE2FromDefaults loads all patterns from security.ExportAllPatterns()
// and builds composite groups with DefaultMaxGroupSize.
func NewCompositeRE2FromDefaults() *CompositeRE2 {
	return NewCompositeRE2(security.ExportAllPatterns(), DefaultMaxGroupSize)
}

// Scan checks input against all composite groups and returns all matches with
// full hit attribution. Returns an empty (non-nil) slice if no match.
// Safe for concurrent calls — holds RLock only, allowing parallel scans.
func (c *CompositeRE2) Scan(input string) []CompositeMatch {
	if len(input) == 0 {
		return []CompositeMatch{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.scanLocked(input)
}

// ScanBytes scans a byte slice. Converts to string and delegates to Scan.
func (c *CompositeRE2) ScanBytes(input []byte) []CompositeMatch {
	if len(input) == 0 {
		return []CompositeMatch{}
	}
	return c.Scan(string(input))
}

// Rebuild replaces all patterns and recompiles all groups atomically.
// Thread-safe via write lock — blocks concurrent Scan calls during rebuild.
func (c *CompositeRE2) Rebuild(patterns []security.ExportedPattern) {
	if patterns == nil {
		patterns = []security.ExportedPattern{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.allPatterns = patterns
	c.buildFrom(patterns)
}

// AddPatterns appends patterns and recompiles affected groups.
// If a pattern with the same Name already exists, it is overwritten.
// Thread-safe via write lock.
func (c *CompositeRE2) AddPatterns(patterns []security.ExportedPattern) {
	c.mu.Lock()
	defer c.mu.Unlock()

	byName := make(map[string]int, len(c.allPatterns))
	for i, p := range c.allPatterns {
		byName[p.Name] = i
	}
	for _, p := range patterns {
		if idx, exists := byName[p.Name]; exists {
			c.allPatterns[idx] = p
		} else {
			byName[p.Name] = len(c.allPatterns)
			c.allPatterns = append(c.allPatterns, p)
		}
	}
	c.buildFrom(c.allPatterns)
}

// RemovePatterns removes patterns by name and recompiles all groups.
// Non-existent names are silently ignored — no error, no warning.
// Thread-safe via write lock.
func (c *CompositeRE2) RemovePatterns(names []string) {
	if len(names) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	toRemove := make(map[string]bool, len(names))
	for _, n := range names {
		toRemove[n] = true
	}
	filtered := make([]security.ExportedPattern, 0, len(c.allPatterns))
	for _, p := range c.allPatterns {
		if !toRemove[p.Name] {
			filtered = append(filtered, p)
		}
	}
	c.allPatterns = filtered
	c.buildFrom(filtered)
}

// GroupCount returns the number of compiled composite groups.
func (c *CompositeRE2) GroupCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.groups)
}

// PatternCount returns the total number of valid compiled patterns across all groups.
// Invalid and degenerate patterns (excluded during construction) are not counted.
func (c *CompositeRE2) PatternCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	total := 0
	for _, entries := range c.reverseIdx {
		total += len(entries)
	}
	return total
}

// MaxGroupSize returns the number of sub-patterns in the largest group.
// Used to verify the group size invariant in tests.
func (c *CompositeRE2) MaxGroupSize() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	max := 0
	for _, entries := range c.reverseIdx {
		if len(entries) > max {
			max = len(entries)
		}
	}
	return max
}

// escalateOnlyPatterns are strong injection SIGNALS that also occur in legitimate
// text (chat-template / role-delimiter markers). A match routes to "escalate"
// (human/second-check) rather than "deny", so the signal is never lost but benign
// documentation of these markers is not hard-blocked. If any non-escalate pattern
// also fires on the same input, deny wins (see engine Tier 3).
var escalateOnlyPatterns = map[string]bool{
	// Chat-template / role-delimiter markers.
	"im_start": true, "im_end": true, "system_marker": true,
	"user_marker": true, "assistant_marker": true, "xml_system_tag": true,
	"sys_marker": true, "sys_end_marker": true,
	// Generic command-chaining separators are ambiguous in isolation (";"/"&"/"&&"
	// are also prose punctuation and URL separators). On their own they escalate;
	// the SPECIFIC dangerous chains (network_chain, file_op_chain, recon_chain, ...)
	// are not listed here and still deny.
	"semicolon_chain": true, "and_chain": true, "or_chain": true,
	"background_chain": true, "newline_chain": true, "cr_chain": true,
}

// escalateOnlyDomains are whole detection domains whose matches route to
// "escalate" rather than "deny". PII is detect-to-REDACT, not block: an email,
// phone, public key, or BIC code appearing in text is sensitive data to flag and
// redact, never a deny-worthy attack. Routing the domain to escalate fixes a class
// of false positives (and is the correct behavior) in one place.
var escalateOnlyDomains = map[string]bool{
	"pii": true,
}

// genericChainPatterns are the broad command-chaining detectors that match any
// "<separator><word>". They are useful but prone to firing on shell control
// keywords; benignKeywordChainOnly suppresses those false positives.
var genericChainPatterns = map[string]bool{
	"semicolon_chain": true, "newline_chain": true,
	"cr_chain": true, "background_chain": true,
	"and_chain": true, "or_chain": true,
}

// shellControlKeywords legitimately follow a separator inside loops/conditionals.
var shellControlKeywords = map[string]bool{
	"do": true, "done": true, "then": true, "else": true,
	"elif": true, "fi": true, "esac": true, "in": true,
}

// chainWordRe captures the first word after each chaining separator.
var chainWordRe = regexp.MustCompile(`(?:;|\n|\r|&)\s*([A-Za-z_]\w*)`)

// benignKeywordChainOnly reports whether EVERY chaining separator in input is
// followed by a shell control keyword (e.g. "; do ... ; done"). If so, a generic
// chaining match is loop/conditional structure, not command chaining. If any
// separator leads to a non-keyword (e.g. "; curl"), it returns false and the
// match stands — so real "; <command>" attacks are unaffected.
func benignKeywordChainOnly(input string) bool {
	// HTML entities (&lt; &gt; &amp; &#39; &quot;) end in ';' and trip the generic
	// semicolon-chain pattern on benign HTML/text. Strip them before inspecting,
	// so "&lt;script&gt;" is not read as command chaining.
	cleaned := htmlEntityRe.ReplaceAllString(input, " ")
	matches := chainWordRe.FindAllStringSubmatch(cleaned, -1)
	if len(matches) == 0 {
		return true // the only separators were inside HTML entities
	}
	for _, m := range matches {
		if !shellControlKeywords[m[1]] {
			return false
		}
	}
	return true
}

// htmlEntityRe matches HTML character entities (named, decimal, hex).
var htmlEntityRe = regexp.MustCompile(`&(?:[a-zA-Z][a-zA-Z0-9]{1,31}|#[0-9]{1,7}|#x[0-9a-fA-F]{1,6});`)

// scanLocked runs the composite scan. Caller must hold c.mu.RLock.
//
// Algorithm:
//  1. For each group, run the compiled alternation against input (O(n) RE2).
//  2. On group hit, run each individual pattern (max DefaultMaxGroupSize entries).
//  3. Collect all CompositeMatch results with full attribution.
func (c *CompositeRE2) scanLocked(input string) []CompositeMatch {
	var results []CompositeMatch
	for _, g := range c.groups {
		if !g.compiled.MatchString(input) {
			continue
		}
		for _, entry := range c.reverseIdx[g.id] {
			matched := entry.compiled.FindString(input)
			if matched == "" {
				continue
			}
			// False-positive guard: the generic command-chaining patterns
			// (semicolon_chain, newline_chain, ...) match "<sep><word>". When that
			// word is a shell control keyword (do/done/then/else/elif/fi/esac/in),
			// it is loop/conditional structure, not a chained command — suppress it.
			// Specific chaining patterns (recon_chain, network_chain, brace_rm_rf,
			// ...) are not in genericChainPatterns and are unaffected. RE2 has no
			// negative lookahead, so this is enforced post-match at the one choke
			// point both the CLI and the engine flow through.
			if genericChainPatterns[entry.name] && benignKeywordChainOnly(input) {
				continue
			}
			results = append(results, CompositeMatch{
				PatternID:  entry.name,
				Domain:     entry.domain,
				Category:   entry.category,
				Severity:   entry.severity,
				Confidence: entry.confidence,
				Matched:    matched,
				GroupID:    g.id,
			})
		}
	}
	if results == nil {
		return []CompositeMatch{}
	}
	return results
}

// buildFrom compiles composite groups from the given patterns.
// Must be called with c.mu held (write) or from the constructor (single-threaded).
//
// Grouping algorithm:
//  1. Validate each pattern via regexp.Compile — skip invalid with slog.Warn.
//  2. Exclude degenerate patterns (those matching empty string) — skip with slog.Warn.
//  3. Sort valid patterns by Domain then Name (deterministic ordering).
//  4. Group by Domain; split each domain's patterns into chunks of c.maxGroupSz.
//  5. Build alternation: (?:p1)|(?:p2)|...|(?:pN) per chunk.
//  6. If alternation compile fails (defensive), fall back to individual groups per pattern.
//  7. Build reverse index: groupID → []patternEntry for hit attribution.
func (c *CompositeRE2) buildFrom(patterns []security.ExportedPattern) {
	type validEntry struct {
		p        security.ExportedPattern
		compiled *regexp.Regexp
	}

	// Step 1+2: validate and filter
	valid := make([]validEntry, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			slog.Warn("composite_re2: skipping invalid pattern",
				"name", p.Name, "domain", p.Domain, "error", err)
			continue
		}
		if re.MatchString("") {
			slog.Warn("composite_re2: skipping degenerate pattern (matches empty string)",
				"name", p.Name, "pattern", p.Pattern)
			continue
		}
		valid = append(valid, validEntry{p: p, compiled: re})
	}

	// Step 3: sort by domain then name (deterministic)
	sort.Slice(valid, func(i, j int) bool {
		if valid[i].p.Domain != valid[j].p.Domain {
			return valid[i].p.Domain < valid[j].p.Domain
		}
		return valid[i].p.Name < valid[j].p.Name
	})

	// Steps 4-7: group by domain, chunk, compile alternation, build reverse index
	var groups []compiledGroup
	reverseIdx := make(map[int][]patternEntry)
	groupID := 0

	for i := 0; i < len(valid); {
		domain := valid[i].p.Domain
		// Collect all entries for this domain
		j := i
		for j < len(valid) && valid[j].p.Domain == domain {
			j++
		}
		domainSlice := valid[i:j]

		// Split into chunks of c.maxGroupSz
		for start := 0; start < len(domainSlice); start += c.maxGroupSz {
			end := start + c.maxGroupSz
			if end > len(domainSlice) {
				end = len(domainSlice)
			}
			chunk := domainSlice[start:end]

			// Build alternation: (?:p1)|(?:p2)|...|(?:pN)
			parts := make([]string, len(chunk))
			for k, e := range chunk {
				parts[k] = "(?:" + e.p.Pattern + ")"
			}
			alt := strings.Join(parts, "|")

			re, err := regexp.Compile(alt)
			if err != nil {
				// Defensive fallback: alternation failed — add each pattern individually.
				slog.Warn("composite_re2: alternation compile failed, falling back to individual groups",
					"domain", domain, "chunk_size", len(chunk), "error", err)
				for _, e := range chunk {
					gid := groupID
					groupID++
					groups = append(groups, compiledGroup{id: gid, compiled: e.compiled, domain: domain})
					reverseIdx[gid] = []patternEntry{{
						name:       e.p.Name,
						compiled:   e.compiled,
						domain:     e.p.Domain,
						category:   e.p.Category,
						severity:   e.p.Severity,
						confidence: e.p.Confidence,
					}}
				}
				continue
			}

			gid := groupID
			groupID++
			groups = append(groups, compiledGroup{id: gid, compiled: re, domain: domain})
			for _, e := range chunk {
				reverseIdx[gid] = append(reverseIdx[gid], patternEntry{
					name:       e.p.Name,
					compiled:   e.compiled,
					domain:     e.p.Domain,
					category:   e.p.Category,
					severity:   e.p.Severity,
					confidence: e.p.Confidence,
				})
			}
		}
		i = j
	}

	c.groups = groups
	c.reverseIdx = reverseIdx
}
