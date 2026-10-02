// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package tiered

import "testing"

// The hardened self-protection patterns must survive the composite RE2 tier
// and input normalization, not only the security package's direct check.
func TestEngineDeniesSelfProtectionBypasses(t *testing.T) {
	e, err := NewEngine(nil)
	if err != nil || !e.Ready() {
		t.Fatalf("engine unavailable: %v", err)
	}
	for _, cmd := range []string{
		"sudo systemctl --now disable guardclaw.service",
		"systemctl kill -s SIGKILL guardclaw",
		"launchctl remove com.guardclaw.daemon",
		"sudo launchctl bootout system/com.guardclaw.daemon",
		"kill -9 $(pgrep guardclaw)",
		"pgrep guardclaw | xargs kill -9",
		"killall -KILL GuardClaw",
		"taskkill /F /IM guardclaw.exe",
	} {
		if r := e.Scan(cmd); r.Decision != "deny" {
			t.Errorf("Scan(%q) = %s (%s), want deny", cmd, r.Decision, r.Reason)
		}
	}
}
