// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security_test

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/TakeInterestInc/guardclaw-core/guardian/security"
)

// firstReleaseSelfProtection are the self-protection regexes exactly as they
// shipped in the first public release (commit 4f6e124). Anything they match
// must still be detected: a rewrite of a gate may add matches, never drop one.
var firstReleaseSelfProtection = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(systemctl|service)\s+(stop|disable|mask)\s+(guardclaw|guardian)(\.service)?\b`),
	regexp.MustCompile(`(?i)\blaunchctl\s+(unload|disable|bootout)\s+.*(guardclaw|guardian)`),
	regexp.MustCompile(`(?i)\b(killall|pkill)\s+.*(guardclaw|guardian)\b`),
	regexp.MustCompile(`(?i)\btaskkill\s+/IM\s+(guardclaw|guardian)(\.exe)?\b`),
	regexp.MustCompile(`(?i)\bsc\s+stop\s+(guardclaw|guardian)\b`),
}

func firstReleaseMatches(s string) bool {
	for _, re := range firstReleaseSelfProtection {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// regressionInputs are inputs the first release denied that a review of the
// rewrite found allowed, plus the pattern examples and the cases each round
// of review named.
var regressionInputs = []string{
	// Pattern examples from the first release.
	"systemctl stop guardclaw",
	"launchctl unload /Library/LaunchDaemons/com.guardclaw.daemon.plist",
	"pkill guardclaw",
	"taskkill /IM guardclaw.exe",
	"sc stop guardclaw",
	// Final-review list.
	"pkill -f 'q|guardclaw '",
	"pkill -f 'q|guardclaw --'",
	"pkill -f 'q|MacOS/guardclaw'",
	`sh -c "pkill -f 'x|guardclaw'"`,
	`bash -c "pkill -f 'x|guardclaw'"`,
	`zsh -lc 'kill $(pgrep -f "q|guardclaw")'`,
	`eval "pkill -f 'x|guardclaw'"`,
	`eval pkill -f "'x|guardclaw'"`,
	"busybox pkill -f 'x|guardclaw'",
	"command -p pkill -f 'x|guardclaw'",
	"exec -a z pkill -f 'x|guardclaw'",
	"time -p pkill -f 'x|guardclaw'",
	"echo 1 | xargs -I{} pkill -f 'x|guardclaw'",
	`watch -n1 "pkill -f 'x|guardclaw'"`,
	`su root -c "pkill -f 'x|guardclaw'"`,
	`sudo sh -c 'systemctl stop guardclaw'`,
	"nohup env A=1 pkill -f 'x|guardclaw' &",
	`bash -c "eval \"pkill -f 'x|guardclaw'\""`,
	// Earlier rounds.
	"pkill -f 'x|guardclaw'",
	"kill $(pgrep -f 'z|guardclaw')",
	"systemctl stop 'x;' guardclaw",
	"pkill -9 -f guardclaw-daemon",
	"killall -KILL GuardClaw",
	"sudo killall guardiand",
	"launchctl bootout gui/501 /Library/LaunchAgents/ai.guardclaw.agent.plist",
}

// TestSelfProtectionNoRegressionVsFirstRelease asserts that every input the
// first release's self-protection regexes matched is still detected by
// CheckCommandInjection and denied by the tiered engine. It covers the named
// inputs above and every line of the corpus.
func TestSelfProtectionNoRegressionVsFirstRelease(t *testing.T) {
	e := newEngine(t)
	inputs := append([]string{}, regressionInputs...)
	for _, dir := range []string{"benign", "malicious"} {
		inputs = append(inputs, loadCorpusLines(t, filepath.Join("..", "..", "testdata", "corpus", dir))...)
	}
	checked := 0
	for _, in := range inputs {
		if !firstReleaseMatches(in) {
			continue
		}
		checked++
		if r := security.CheckCommandInjection(in); !r.Detected || r.Score < 1.0 {
			t.Errorf("%q: first release detected, CheckCommandInjection now %+v", in, r)
		}
		if r := e.Scan(in); r.Decision != "deny" {
			t.Errorf("%q: first release denied, engine now %s (%v)", in, r.Decision, r.MatchedPatterns)
		}
	}
	if checked < 20 {
		t.Fatalf("only %d inputs matched the first-release regexes; the table lost coverage", checked)
	}
	t.Logf("%d inputs matched by the first release; all still detected and denied", checked)
}

// TestSelfProtectionNamedBypassesDenied asserts the whole final-review list is
// denied by the new analyzer on its own, not only through the backstop.
func TestSelfProtectionNamedBypassesDenied(t *testing.T) {
	for _, in := range regressionInputs {
		if _, ok := security.MatchSelfProtection(in); !ok {
			t.Errorf("MatchSelfProtection(%q) = false, want true", in)
		}
	}
	// Nesting beyond the bound fails closed.
	if _, ok := security.MatchSelfProtection(strings.Repeat("eval ", 20) + "true"); !ok {
		t.Error("deeply nested eval did not fail closed")
	}
	if _, ok := security.MatchSelfProtection(`sh -c "echo hello; ls -la"`); ok {
		t.Error("benign sh -c flagged")
	}
}
