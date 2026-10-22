// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import "testing"

// Grouping is evaluated only for supported regular-expression targets. It
// must not turn a distinct literal/glob service or image name into a guard.
func TestGroupingTargetsRespectToolSemantics(t *testing.T) {
	for _, command := range []string{
		`pkill 'gu(a)rd(c)law'`,
		`pkill -x 'gu(a)rd(c)law'`,
		`killall -r 'gu(a)rd(c)law'`,
		`killall --regexp 'gu(a)rd(c)law'`,
		`pgrep 'gu(a)rd(c)law' | xargs kill`,
	} {
		if _, ok := MatchSelfProtection(command); !ok {
			t.Errorf("regex guard target %q not detected", command)
		}
	}
	for _, command := range []string{
		`systemctl stop 'gu(a)rd(c)law'`,
		`service 'gu(a)rd(c)law' stop`,
		`launchctl stop 'gu(a)rd(c)law'`,
		`taskkill -im 'gu(a)rd(c)law.exe'`,
		`killall 'gu(a)rd(c)law'`,
	} {
		if _, ok := MatchSelfProtection(command); ok {
			t.Errorf("distinct literal/glob name %q detected", command)
		}
	}
}
