// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package tiered

import (
	"fmt"
	"io"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
)

// ACMatcher wraps the BobuSumisu Aho-Corasick trie with GuardClaw-specific
// pattern metadata and serialization support.
//
// Design: ACMatcher is the only place in the codebase that imports the
// BobuSumisu library. All callers use ACMatcher, which enables a future
// library swap (e.g., to pgavlin for Phase 3 memory optimization) without
// touching any caller code.
//
// Thread safety: (*ahocorasick.Trie).MatchString is safe for concurrent reads
// after Build(). ACMatcher itself is immutable after construction — no mutex
// needed. Scan/ScanBytes/ScanFirst may be called concurrently.
type ACMatcher struct {
	trie     *ahocorasick.Trie
	patterns []string // original patterns in insertion order (index == pattern ID)
	count    int      // len(patterns), cached to avoid repeated len() calls
}

// ACMatch represents a single match result from the AC automaton.
type ACMatch struct {
	PatternID int    // 0-based index in the patterns slice provided to NewACMatcher
	Pattern   string // the matched literal string
	Position  int    // start byte offset in the input (0-indexed)
}

// NewACMatcher builds an ACMatcher from a list of literal string patterns.
// An empty (or nil) patterns slice is valid — Scan will return zero matches.
func NewACMatcher(patterns []string) (*ACMatcher, error) {
	if patterns == nil {
		patterns = []string{}
	}
	b := ahocorasick.NewTrieBuilder()
	if len(patterns) > 0 {
		b.AddStrings(patterns)
	}
	trie := b.Build()
	return &ACMatcher{
		trie:     trie,
		patterns: patterns,
		count:    len(patterns),
	}, nil
}

// NewACMatcherFromReader deserializes a pre-built AC trie from the gzip+binary
// format written by Encode. Used at daemon startup with go:embed data or an
// external file.
//
// The patterns slice must match the insertion order used when the trie was
// originally built — the BobuSumisu serialization format encodes the automaton
// structure but not the original pattern strings.
func NewACMatcherFromReader(r io.Reader, patterns []string) (*ACMatcher, error) {
	trie, err := ahocorasick.Decode(r)
	if err != nil {
		return nil, fmt.Errorf("ahocorasick: decode: %w", err)
	}
	if patterns == nil {
		patterns = []string{}
	}
	return &ACMatcher{
		trie:     trie,
		patterns: patterns,
		count:    len(patterns),
	}, nil
}

// Scan runs the AC automaton over the input string and returns all matches.
// Returns an empty (non-nil) slice for empty input or zero patterns.
// Safe for concurrent calls after construction.
func (m *ACMatcher) Scan(input string) []ACMatch {
	if m.count == 0 || len(input) == 0 {
		return []ACMatch{}
	}
	raw := m.trie.MatchString(input)
	return m.toACMatches(raw)
}

// ScanBytes runs the AC automaton over a byte slice input.
// Returns an empty (non-nil) slice for nil or empty input.
// Safe for concurrent calls after construction.
func (m *ACMatcher) ScanBytes(input []byte) []ACMatch {
	if m.count == 0 || len(input) == 0 {
		return []ACMatch{}
	}
	raw := m.trie.Match(input)
	return m.toACMatches(raw)
}

// ScanFirst returns the first match found in the input, or nil if no match.
// More efficient than Scan when only an existence check is needed.
// Safe for concurrent calls after construction.
func (m *ACMatcher) ScanFirst(input string) *ACMatch {
	if m.count == 0 || len(input) == 0 {
		return nil
	}
	raw := m.trie.MatchFirstString(input)
	if raw == nil {
		return nil
	}
	matched := raw.MatchString()
	match := &ACMatch{
		PatternID: int(raw.Pattern()),
		Pattern:   matched,
		Position:  int(raw.Pos()),
	}
	return match
}

// Encode serializes the underlying trie to gzip+binary format compatible with
// NewACMatcherFromReader. Used at build/CI time to pre-serialize the automaton.
func (m *ACMatcher) Encode(w io.Writer) error {
	if err := ahocorasick.Encode(w, m.trie); err != nil {
		return fmt.Errorf("ahocorasick: encode: %w", err)
	}
	return nil
}

// PatternCount returns the number of patterns in the automaton.
func (m *ACMatcher) PatternCount() int {
	return m.count
}

// toACMatches converts raw library Match pointers to ACMatch values.
// match.Pos() returns the START byte offset of the match (0-indexed).
func (m *ACMatcher) toACMatches(raw []*ahocorasick.Match) []ACMatch {
	result := make([]ACMatch, 0, len(raw))
	for _, r := range raw {
		matched := r.MatchString()
		result = append(result, ACMatch{
			PatternID: int(r.Pattern()),
			Pattern:   matched,
			Position:  int(r.Pos()),
		})
	}
	return result
}
