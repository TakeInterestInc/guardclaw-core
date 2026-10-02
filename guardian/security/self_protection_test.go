// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import "testing"

func TestSelfProtectionCommandPatterns(t *testing.T) {
	selfProtect := map[string]bool{
		"guardclaw_service_stop":      true,
		"guardclaw_launchctl_disable": true,
		"guardclaw_process_kill":      true,
		"guardclaw_taskkill":          true,
		"guardclaw_sc_stop":           true,
	}
	hits := []struct{ cmd, want string }{
		// systemd
		{"systemctl stop guardclaw", "guardclaw_service_stop"},
		{"sudo systemctl --now disable guardclaw.service", "guardclaw_service_stop"},
		{"systemctl --user stop guardclaw-daemon", "guardclaw_service_stop"},
		{"systemctl kill -s SIGKILL guardclaw", "guardclaw_service_stop"},
		{"systemctl mask guardian.service", "guardclaw_service_stop"},
		{"service guardclaw stop", "guardclaw_service_stop"},
		// launchd
		{"launchctl unload /Library/LaunchDaemons/com.guardclaw.daemon.plist", "guardclaw_launchctl_disable"},
		{"launchctl remove com.guardclaw.daemon", "guardclaw_launchctl_disable"},
		{"sudo launchctl bootout system/com.guardclaw.daemon", "guardclaw_launchctl_disable"},
		{"launchctl bootout gui/501 /Library/LaunchAgents/ai.guardclaw.agent.plist", "guardclaw_launchctl_disable"},
		{"launchctl kill SIGTERM system/com.guardclaw.daemon", "guardclaw_launchctl_disable"},
		// processes
		{"pkill guardclaw", "guardclaw_process_kill"},
		{"pkill -9 -f guardclaw-daemon", "guardclaw_process_kill"},
		{"killall -KILL GuardClaw", "guardclaw_process_kill"},
		{"sudo killall guardiand", "guardclaw_process_kill"},
		{"kill -9 $(pgrep guardclaw)", "guardclaw_process_kill"},
		{"kill `pgrep -f guardclaw`", "guardclaw_process_kill"},
		{"kill $(pidof guardclaw)", "guardclaw_process_kill"},
		{"pgrep guardclaw | xargs kill -9", "guardclaw_process_kill"},
		{"PID=$(pgrep -f guardclaw); kill -9 $PID", "guardclaw_process_kill"},
		// Windows
		{"taskkill /F /IM guardclaw.exe", "guardclaw_taskkill"},
		{"sc stop guardclaw", "guardclaw_sc_stop"},
		{"taskkill /im guardclaw*", "guardclaw_taskkill"},
		{`taskkill /f /fi "imagename eq guardclaw*"`, "guardclaw_taskkill"},
		{"Stop-Process -Name guardclaw -Force", "guardclaw_taskkill"},
		{"sc.exe stop guardclaw", "guardclaw_sc_stop"},
		{"sc config guardclaw start= disabled", "guardclaw_sc_stop"},
		{"Stop-Service -Name GuardClaw -Force", "guardclaw_sc_stop"},
		{"Set-Service -Name guardclaw -StartupType Disabled", "guardclaw_sc_stop"},
		// Regex and glob targets: pkill -f / pgrep -f read the target as a regex.
		{"pkill guard[c]law", "guardclaw_process_kill"},
		{"pkill -f 'guard.law'", "guardclaw_process_kill"},
		{"pkill -f guardcla", "guardclaw_process_kill"},
		{"pkill -f 'guardcl.w'", "guardclaw_process_kill"},
		{"pkill -f uardclaw", "guardclaw_process_kill"},
		{"pkill -f 'gu.*claw'", "guardclaw_process_kill"},
		{"killall 'g[u]ardian'", "guardclaw_process_kill"},
		{"kill -9 $(pgrep -f 'guard[c]law')", "guardclaw_process_kill"},
		// Shell quoting and escapes spliced into the name.
		{`systemctl stop guard\claw`, "guardclaw_service_stop"},
		{`systemctl stop g"u"ardclaw`, "guardclaw_service_stop"},
		{"systemctl stop 'guardcl*'", "guardclaw_service_stop"},
		{`launchctl bootout system/com.guard\claw.daemon`, "guardclaw_launchctl_disable"},
		// Removing or moving the guard's own service files.
		{"sudo rm /Library/LaunchDaemons/com.guardclaw.daemon.plist", "guardclaw_launchctl_disable"},
		{"rm -f /Library/LaunchDaemons/com.guardclaw*.plist", "guardclaw_launchctl_disable"},
		{"mv ~/Library/LaunchAgents/ai.guardclaw.agent.plist /tmp/", "guardclaw_launchctl_disable"},
		{"sudo rm /etc/systemd/system/guardclaw.service", "guardclaw_service_stop"},
		{"mv /lib/systemd/system/guardclaw-daemon.service /root/", "guardclaw_service_stop"},
	}
	for _, tc := range hits {
		var matched []string
		for _, p := range CommandInjectionPatterns {
			if selfProtect[p.Name] && p.Pattern.MatchString(tc.cmd) {
				matched = append(matched, p.Name)
			}
		}
		found := false
		for _, m := range matched {
			if m == tc.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: self-protection matches %v, want %s", tc.cmd, matched, tc.want)
		}
		if r := CheckCommandInjection(tc.cmd); !r.Detected || r.Score < 1.0 {
			t.Errorf("%q: CheckCommandInjection = %+v, want a severity-1.0 detection", tc.cmd, r)
		}
	}

	misses := []string{
		"systemctl status guardclaw",
		"systemctl restart nginx",
		"systemctl stop nginx && cat guardian.log",
		"launchctl list | grep guardclaw",
		"launchctl print system/com.guardclaw.daemon",
		"pgrep guardclaw",
		"kill -9 4242",
		"pkill node",
		"service guardclaw status",
		"echo guardclaw is running",
		// Command boundaries: a separator, pipe or comment ends the command.
		"pgrep guardian || echo nothing to kill",
		"pgrep -l guardclaw; ./kill-switch.sh",
		"grep -r kill docs | grep pgrep | grep guardian",
		"pkill something  # guardclaw note",
		"kill -9 4242; pgrep guardclaw",
		"sc query guardclaw",
		"Get-Service guardclaw",
		"taskkill /IM notepad.exe",
		"rm /Library/LaunchDaemons/com.example.daemon.plist",
		"cat /etc/systemd/system/guardclaw.service",
		"launchctl print system/com.guard\\claw.daemon",
	}
	for _, cmd := range misses {
		for _, p := range CommandInjectionPatterns {
			if selfProtect[p.Name] && p.Pattern.MatchString(cmd) {
				t.Errorf("%q: unexpectedly matched self-protection pattern %s", cmd, p.Name)
			}
		}
	}
}
