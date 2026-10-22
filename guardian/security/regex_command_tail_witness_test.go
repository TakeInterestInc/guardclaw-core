// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"regexp"
	"testing"
)

// Actual RE2 matches are independent positive witnesses for the symbolic
// suffix search. Include non-ASCII case-folding and newline boundary cases.
func TestCommandTailSearchRetainsConcreteRE2Witnesses(t *testing.T) {
	patterns := []string{
		`[g]uardian a+`, `[g]uardian [^-]+`, `[g]uardian (?:a|-){1,3}`,
		`[g]uardian K\B$`, `[g]uardian \ba`, `[g]uardian \B-`,
		`[g]uardian (?m:a$)\n`, `[g]uardian (?:\p{Greek}|K)$`,
		`[g]uardian \x{FFFD}$`, `[g]uardian \S+`,
	}
	for _, pattern := range patterns {
		re := regexp.MustCompile(`(?i)(?:` + pattern + `)`)
		witness := false
		for _, tail := range []string{"a", "aaa", "-", "--a", "K", "\u212a", "a\n", "\u03b1", "\ufffd"} {
			if re.MatchString("guardian " + tail) {
				witness = true
				if !fullCommandTargetPossible(pattern, false) {
					t.Errorf("pattern %q missed actual RE2 witness %q", pattern, tail)
				}
			}
		}
		if !witness {
			t.Errorf("test pattern %q has no concrete witness", pattern)
		}
	}
	for _, pattern := range []string{
		`[g]uardian \b\B.*`, `[g]uardian \z.`,
		`[g]uardian \x00`, `(?-i:[g]uardian K\B$)`,
	} {
		if fullCommandTargetPossible(pattern, false) {
			t.Errorf("impossible command tail %q accepted", pattern)
		}
	}
}
