// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"os"
	"os/exec"
	"path/filepath"
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
		file  bool
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
		{flags: []string{"-ni"}, file: true},
		{flags: []string{"-n", "+n"}, file: true},
		{flags: []string{"-n", "--"}, after: []string{"+n"}, file: true},
		{after: []string{"-n"}, file: true},
	} {
		// Only a fixed printf marker is run. Download/attack samples are never
		// executed, and inherited startup files/environment are excluded.
		home := t.TempDir()
		program := "printf guardclaw-option-oracle"
		if test.file {
			filename := filepath.Join(home, "script.sh")
			if err := os.WriteFile(filename, []byte(program), 0600); err != nil {
				t.Fatal(err)
			}
			program = filename
		}
		operands := append([]string(nil), test.flags...)
		operands = append(operands, program)
		operands = append(operands, test.after...)
		var words []shWord
		for _, operand := range operands {
			words = append(words, shWord{text: operand})
		}
		args := append([]string{"--noprofile", "--norc"}, operands...)
		cmd := exec.Command(bash, args...)
		cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin", "HISTFILE=" + home + "/history"}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("bash flags %v after %v file=%v: %v", test.flags, test.after, test.file, err)
		}
		if got, want := shellSyntaxOnly("bash", words), len(out) == 0; got != want {
			t.Errorf("flags %v after %v file=%v: syntaxOnly=%v, actual printf suppressed=%v", test.flags, test.after, test.file, got, want)
		}
	}
}
