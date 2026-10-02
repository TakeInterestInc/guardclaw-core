// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"strings"
	"testing"
	"time"
)

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
		{"pkill -f 'guardcl.*'", "guardclaw_process_kill"},
		{"pgrep -f 'guard.*' | xargs kill", "guardclaw_process_kill"},
		{"pkill -x 'guard(claw|ian)'", "guardclaw_process_kill"},
		{"pkill -F /var/run/guardclaw.pid", "guardclaw_process_kill"},
		{"kill $(cat /var/run/guardclaw.pid)", "guardclaw_process_kill"},
		{"echo $(pkill guardclaw)", "guardclaw_process_kill"},
		{"(pkill guardclaw)", "guardclaw_process_kill"},
		{"{ pkill guardclaw; }", "guardclaw_process_kill"},
		{"pkill -v node", "guardclaw_process_kill"},
		{"/usr/bin/pkill -9 guardclaw", "guardclaw_process_kill"},
		{"env FOO=1 nohup pkill guardclaw", "guardclaw_process_kill"},
		// Quotes and $( ) are respected when splitting commands.
		{"pkill -f 'x|guardclaw'", "guardclaw_process_kill"},
		{`pkill -f "a|b|guardclaw"`, "guardclaw_process_kill"},
		{"kill $(pgrep -f 'z|guardclaw')", "guardclaw_process_kill"},
		{"kill -9 `pgrep -f 'a#b|guardclaw'`", "guardclaw_process_kill"},
		{"systemctl stop 'x;' guardclaw", "guardclaw_service_stop"},
		{`systemctl stop "x|y" guardclaw.service`, "guardclaw_service_stop"},
		{"launchctl bootout 'gui/501;' com.guardclaw.daemon", "guardclaw_launchctl_disable"},
		{"Get-Service guardclaw | Stop-Service", "guardclaw_sc_stop"},
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
	matchedNames := func(cmd string) []string {
		var matched []string
		for _, p := range CommandInjectionPatterns {
			if selfProtect[p.Name] && p.Pattern.MatchString(cmd) {
				matched = append(matched, p.Name)
			}
		}
		if n, ok := MatchSelfProtection(cmd); ok {
			matched = append(matched, n)
		}
		return matched
	}
	for _, tc := range hits {
		matched := matchedNames(tc.cmd)
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
		"kill -9 4242; pgrep guardclaw",
		"sc query guardclaw",
		"Get-Service guardclaw",
		"taskkill /IM notepad.exe",
		"rm /Library/LaunchDaemons/com.example.daemon.plist",
		"cat /etc/systemd/system/guardclaw.service",
		"launchctl print system/com.guard\\claw.daemon",
		// Ordinary regex and name targets that do not select a guard.
		"pkill -f 'node.*claude'",
		"pkill -f 'python.*claim'",
		"pkill -f 'law.*'",
		"pkill safeguard",
		"pkill -f vanguard-agent",
		"killall guardduty-agent",
		"pkill -f guardrail",
		"pkill -f claw",
		"pkill -x guardcla",
		"systemctl stop safeguard",
		"systemctl stop vanguard-agent guardduty-agent",
		"sudo systemctl stop 'guardrail*'",
		"git commit -m 'stop guardclaw service docs'",
	}
	for _, cmd := range misses {
		if m := matchedNames(cmd); len(m) > 0 {
			t.Errorf("%q: unexpectedly matched self-protection %v", cmd, m)
		}
	}
}

func TestMatchSelfProtectionBoundedOnAdversarialInput(t *testing.T) {
	big := func(unit string, n int) string { return strings.Repeat(unit, n/len(unit)+1)[:n] }
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"many pkill targets fail closed", big("pkill -f 'node.*claude'; ", 64<<10), true},
		{"deep nesting fails closed", strings.Repeat("$(", 4000) + "true", true},
		{"long regex target fails closed", "pkill -f '" + strings.Repeat("(a|b)*", 200) + "'", true},
		{"long benign command list", big("echo hello world; ls -la | grep x && cd /tmp; ", 64<<10), false},
		{"unclosed nested substitutions fail closed", big("echo 'a \"b $(c `d ", 64<<10), true},
		{"unterminated quotes", "echo 'it" + big("s fine \" x ", 64<<10), false},
		{"worst-case regex targets under budget", strings.Repeat("pkill -f '"+strings.Repeat("[a-z]*", 40)+"x'; ", spRegexBudget), false},
	}
	for _, tc := range cases {
		start := time.Now()
		_, got := MatchSelfProtection(tc.input)
		elapsed := time.Since(start)
		if got != tc.want {
			t.Errorf("%s: matched = %v, want %v", tc.name, got, tc.want)
		}
		if elapsed > 250*time.Millisecond {
			t.Errorf("%s: took %v on %d bytes, want < 250ms", tc.name, elapsed, len(tc.input))
		}
		t.Logf("%s: %v (%d bytes)", tc.name, elapsed, len(tc.input))
	}
}

func BenchmarkMatchSelfProtection64KiB(b *testing.B) {
	in := strings.Repeat("systemctl status nginx; kill -9 $(pgrep -f 'node.*claude') | tee log; ", 1000)[:64<<10]
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = MatchSelfProtection(in)
	}
}

// The backstop keeps the first release's own false positives: its process
// regex reads past a shell comment. These stay flagged by design.
func TestBackstopKeepsFirstReleaseFalsePositives(t *testing.T) {
	for _, cmd := range []string{
		"pkill something  # guardclaw note",
		"pkill -f 'x' # guardclaw",
	} {
		if r := CheckCommandInjection(cmd); !r.Detected || r.PatternName != "guardclaw_process_kill" {
			t.Errorf("%q: CheckCommandInjection = %+v, want guardclaw_process_kill (first-release behavior)", cmd, r)
		}
		if _, ok := MatchSelfProtection(cmd); ok {
			t.Errorf("%q: MatchSelfProtection = true; only the backstop should flag it", cmd)
		}
	}
}
