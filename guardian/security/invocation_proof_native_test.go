// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0
package security

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Only fixed printf programs run. sh/dash can resolve to one implementation;
// these observations certify their installed versions, not universal profiles.
func TestInvocationProfileNativeSourceMarkers(t *testing.T) {
	for _, tc := range []struct {
		name               string
		args               []string
		mode, source, want string
	}{
		{"sh", []string{"-a", "fixed.sh", "data.sh"}, "file", "fixed.sh", "FILE_FIXED"},
		{"dash", []string{"-b", "fixed.sh", "data.sh"}, "file", "fixed.sh", "FILE_FIXED"},
		{"dash", []string{"-C", "fixed.sh", "data.sh"}, "file", "fixed.sh", "FILE_FIXED"},
		{"bash", []string{"-co", "errexit", "printf INLINE_FIXED", "data.sh"}, "inline", "printf INLINE_FIXED", "INLINE_FIXED"},
		{"zsh", []string{"-b", "-n", "data.sh"}, "file", "-n", "SOURCE_DASH_N"},
		{"zsh", []string{"-b", "--", "data.sh"}, "file", "--", "SOURCE_DOUBLE_DASH"},
		{"zsh", []string{"-bc", "printf INLINE_FIXED", "data.sh"}, "inline", "printf INLINE_FIXED", "INLINE_FIXED"},
		{"zsh", []string{"-cb", "printf INLINE_FIXED", "data.sh"}, "inline", "printf INLINE_FIXED", "INLINE_FIXED"},
	} {
		t.Run(tc.name+"/"+tc.args[0], func(t *testing.T) {
			binary, err := exec.LookPath(tc.name)
			if err != nil {
				t.Skipf("%s unavailable; native profile not validated", tc.name)
			}
			home := t.TempDir()
			for name, program := range map[string]string{"fixed.sh": "printf FILE_FIXED", "data.sh": "printf DATA_MUST_NOT_EXECUTE", "-n": "printf SOURCE_DASH_N", "--": "printf SOURCE_DOUBLE_DASH"} {
				if err := os.WriteFile(filepath.Join(home, name), []byte(program), 0600); err != nil {
					t.Fatal(err)
				}
			}
			words := make([]shWord, len(tc.args))
			for i, arg := range tc.args {
				words[i] = shWord{text: arg, rawSource: "'" + arg + "'"}
			}
			proof := readShellInvocation(tc.name, words)
			if proof.mode != tc.mode || proof.selected < 0 || words[proof.selected].text != tc.source {
				t.Fatalf("wrong source ownership: %+v", proof)
			}
			for i := proof.selected + 1; i < len(words); i++ {
				if proof.roles[i] != invocationData {
					t.Fatalf("later data not excluded at%d", i)
				}
			}
			args := tc.args
			if tc.name == "bash" {
				args = append([]string{"--noprofile", "--norc"}, args...)
			}
			cmd := exec.Command(binary, args...)
			cmd.Dir = home
			cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin", "LC_ALL=C"}
			out, err := cmd.Output()
			if err != nil || string(out) != tc.want {
				t.Fatalf("native selected source mismatch: out=%q want=%q err=%v", out, tc.want, err)
			}
		})
	}
}
