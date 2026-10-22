// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"os/exec"
	"testing"
)

func TestShellSyntaxOnlyBashOracle(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable for harmless option oracle")
	}
	for _, test := range []struct {
		flags []string
		after []string
	}{
		{flags: []string{"-n", "-c"}},
		{flags: []string{"-nc"}},
		{flags: []string{"-n", "+n", "-c"}},
		{flags: []string{"-nic"}},
		{flags: []string{"-o", "noexec", "-c"}},
		{flags: []string{"-o", "noexec", "+o", "noexec", "-c"}},
		{flags: []string{"-O", "extglob", "-n", "-c"}},
		{flags: []string{"-c"}, after: []string{"-n"}},
		{flags: []string{"-n", "-c"}, after: []string{"+n"}},
	} {
		// Only a fixed printf marker is run. Download/attack samples are never
		// executed, and inherited startup files/environment are excluded.
		operands := append([]string(nil), test.flags...)
		operands = append(operands, "printf guardclaw-option-oracle")
		operands = append(operands, test.after...)
		var words []shWord
		for _, operand := range operands {
			words = append(words, shWord{text: operand})
		}
		args := append([]string{"--noprofile", "--norc"}, operands...)
		cmd := exec.Command(bash, args...)
		home := t.TempDir()
		cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin", "HISTFILE=" + home + "/history"}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("bash flags %v after %v: %v", test.flags, test.after, err)
		}
		if got, want := shellSyntaxOnly("bash", words), len(out) == 0; got != want {
			t.Errorf("flags %v after %v: syntaxOnly=%v, actual printf suppressed=%v", test.flags, test.after, got, want)
		}
	}
}
