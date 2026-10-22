// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import "testing"

func TestCleanupProtectedPathAliases(t *testing.T) {
	resetRegistry(t)
	checker := NewDefaultWithSystemProtectedPathChecker()
	for _, fold := range []bool{false, true} {
		withCaseFolding(t, fold, func() {
			for _, path := range []string{
				"/Volumes/Macintosh HD/etc/passwd",
				"/Volumes/Data/var/log/auth.log",
				"/Volumes/Data/etc/../etc/sudoers",
				"/home/alice/project/.guardclaw",
				"/home/alice/project/.guardclaw/",
				"sub/project/.guardclaw",
				"/proc/1/root/etc/shadow",
				"/proc/234/root/home/alice/.ssh/id_ed25519",
				"/proc/234/root",
				"/proc/thread-self/root/etc/passwd",
				"/proc/1/root/../etc/shadow",
				"/tmp/../proc/1/./root/../../etc/shadow",
				"/proc/2/../1/root/../etc/shadow",
			} {
				if !checker.IsProtected(path) {
					t.Errorf("fold=%v: %q not protected", fold, path)
				}
			}
			for _, path := range []string{
				"/Volumes/USB/etc/notes.txt",
				"/Volumes/USB/etcetera/passwd",
				"/Volumes/USB/variable/log/auth.log",
				"/home/alice/project/.guardclaw-notes",
				"/home/alice/project/.guardclaw.json",
				"/proc/234/rooted/notes.txt",
				"/proc/234/status",
			} {
				if checker.IsProtected(path) {
					t.Errorf("fold=%v: ordinary path %q protected", fold, path)
				}
			}
		})
	}
	if NewProtectedPathChecker([]string{"only/this.txt"}).IsProtected("/proc/1/root/notes.txt") {
		t.Error("custom policy unexpectedly inherited procfs system protection")
	}
}

func TestCleanupTaskkillDashOptions(t *testing.T) {
	for _, command := range []string{
		"taskkill -f -im guardclaw.exe",
		"taskkill -IM guardian.exe",
		`taskkill -fi "imagename eq guardclaw*"`,
		`taskkill /f -fi "imagename eq guardian.exe"`,
	} {
		if name, ok := MatchSelfProtection(command); !ok || name != selfProtectTaskkill {
			t.Errorf("MatchSelfProtection(%q) = %q, %v", command, name, ok)
		}
		if result := CheckCommandInjection(command); !result.Detected {
			t.Errorf("CheckCommandInjection(%q) not detected", command)
		}
		matched := false
		for _, pattern := range CommandInjectionPatterns {
			if pattern.Name == selfProtectTaskkill && pattern.Pattern.MatchString(command) {
				matched = true
			}
		}
		if !matched {
			t.Errorf("exported taskkill pattern does not match %q", command)
		}
	}
	for _, command := range []string{"taskkill -im notepad.exe", `taskkill -fi "imagename eq editor.exe"`} {
		if name, ok := MatchSelfProtection(command); ok {
			t.Errorf("ordinary command %q detected as %s", command, name)
		}
	}
}
