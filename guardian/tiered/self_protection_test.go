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
		"taskkill /im guardclaw*",
		"sc.exe stop guardclaw",
		"Stop-Service -Name guardclaw",
		"pkill -f 'guardcl.w'",
		"pkill guard[c]law",
		"pkill -f uardclaw",
		`systemctl stop guard\claw`,
		"sudo rm /Library/LaunchDaemons/com.guardclaw.daemon.plist",
		"sudo rm /etc/systemd/system/guardclaw.service",
		"PID=$(pgrep -f guardclaw); kill -9 $PID",
		"pkill -f 'x|guardclaw'",
		"kill $(pgrep -f 'z|guardclaw')",
		"systemctl stop 'x;' guardclaw",
		"pkill -f 'guardcl.*'",
	} {
		if r := e.Scan(cmd); r.Decision != "deny" {
			t.Errorf("Scan(%q) = %s (%s), want deny", cmd, r.Decision, r.Reason)
		}
	}
	// Separate commands that only mention a guard name. Generic chaining
	// patterns may still escalate these; none may be denied.
	for _, cmd := range []string{
		"pgrep guardian || echo nothing to kill",
		"pgrep -l guardclaw; ./kill-switch.sh",
		"grep -r kill docs | grep pgrep | grep guardian",
		"kill -9 4242; pgrep guardclaw",
		"pkill -f 'node.*claude'",
		"pkill -f 'python.*claim'",
		"pkill -f 'law.*'",
		"pkill safeguard",
		"pkill -f vanguard-agent",
		"killall guardduty-agent",
		"pkill -f guardrail",
	} {
		if r := e.Scan(cmd); r.Decision == "deny" {
			t.Errorf("Scan(%q) = deny (%v), want allow or escalate", cmd, r.MatchedPatterns)
		}
	}
}
