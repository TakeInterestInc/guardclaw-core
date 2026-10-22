// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import "testing"

func TestFullCommandTargetsIncludeArguments(t *testing.T) {
	for _, command := range []string{
		`pkill -f 'x|[g]uardian '`,
		`pkill --full 'x|[g]uardian '`,
		`pkill -fx '[g]uardian .*'`,
		`pkill -f '[g]uardclaw\s'`,
		`kill $(pgrep --full 'x|[g]uardian ')`,
		`pkill -f '[g]uardian --daemon'`,
		`pkill -f '[g]uardian --config=/tmp/custom'`,
		`pkill -fx '[g]uardian --config=/tmp/custom'`,
		`pkill -f '[g]uardian \bnode'`,
		`pkill -f '[g]uardian \B--daemon'`,
		`pkill -f '[g]uardian --K\B$'`,
	} {
		if _, ok := MatchSelfProtection(command); !ok {
			t.Errorf("guard target %q not detected", command)
		}
		if !CheckCommandInjection(command).Detected || !CheckAgentCommand(command).Detected {
			t.Errorf("guard target %q admitted by a command checker", command)
		}
	}
	for _, command := range []string{
		`pkill 'x|[g]uardian '`,
		`pkill -f 'node.*claude'`,
		`pkill -f -- '--config'`,
		`pgrep -f '[g]uardian '`,
		`pkill -f '[g]uardian \b\B--daemon'`,
		`pkill -f '$[g]uardian '`,
		`pkill -f '[g]uardian [\x00]'`,
		`pkill -f '(?-i:[g]uardian --K\B$)'`,
	} {
		if _, ok := MatchSelfProtection(command); ok {
			t.Errorf("ordinary command %q detected", command)
		}
	}
}

func TestRegexTargetMemoizationKeepsModeAndBudget(t *testing.T) {
	state := &spState{budget: 4}
	if !state.regexSelectsGuard(`[g]uardian `, false, true) {
		t.Fatal("full command mode did not match the argument separator")
	}
	if state.regexSelectsGuard(`[g]uardian `, false, false) {
		t.Fatal("full-command result leaked into process-name mode")
	}
	if state.regexSelectsGuard(`node.*claude`, false, true) || state.regexSelectsGuard(`node.*claude`, false, true) {
		t.Fatal("ordinary repeated target matched")
	}
	if !state.regexSelectsGuard(`node.*claude`, false, true) {
		t.Fatal("memoized targets bypassed the per-command compilation budget")
	}
}
