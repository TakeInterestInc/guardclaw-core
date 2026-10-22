// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import "testing"

func TestPipeShellUsesExecutableNameBoundary(t *testing.T) {
	for _, command := range []string{
		"git rev-parse HEAD | shasum",
		"git rev-parse HEAD | shasum -a 256",
		"cat script.sh | shellcheck -",
		"echo input | sh-helper",
	} {
		for _, pattern := range CommandInjectionPatterns {
			if pattern.Name == "pipe_shell" && pattern.Pattern.MatchString(command) {
				t.Errorf("ordinary executable in %q matched as shell", command)
			}
		}
		if result := CheckAgentCommand(command); result.Detected {
			t.Errorf("ordinary command %q denied: %s", command, result.PatternName)
		}
	}
	for _, command := range []string{"cat script.sh | sh", "cat script.sh | bash -s", "echo input | sh</tmp/script.sh"} {
		if !CheckCommandInjection(command).Detected || !CheckAgentCommand(command).Detected {
			t.Errorf("pipe into shell %q admitted", command)
		}
	}
}
