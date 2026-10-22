// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestLiteralDownloadQuoteBashOracle(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable for harmless literal-word oracle")
	}
	for _, spelling := range []string{
		"'$x.sh'", "'*.sh'", "\\$x.sh", "\\*.sh",
		"'$(not-run).sh'", "'>x.sh'", "$'\\x24x.sh'", "\"$.sh\"",
	} {
		// Every spelling above is fixed and literal. This runs only printf;
		// neither download strings nor a substitution is executed.
		cmd := exec.Command(bash, "--noprofile", "--norc", "-c", "printf %s "+spelling)
		cmd.Env = []string{"HOME=" + t.TempDir(), "PATH=/usr/bin:/bin"}
		actual, err := cmd.Output()
		if err != nil {
			t.Fatalf("literal word %q: %v", spelling, err)
		}
		p := &shParser{s: "printf %s " + spelling}
		commands := p.parseList(0)
		if p.overflow || len(commands) != 1 || len(commands[0].words) != 3 {
			t.Fatalf("literal word %q did not parse", spelling)
		}
		word := commands[0].words[2]
		if got, ok := literalDownloadPath(word); !ok || got != string(actual) {
			t.Errorf("word %q: literal=%v canonical=%q native=%q", spelling, ok, got, actual)
		}
	}
}

func TestNonBashNoexecCanBeReenabled(t *testing.T) {
	for _, name := range []string{"sh", "dash"} {
		t.Run(name, func(t *testing.T) {
			shell, err := exec.LookPath(name)
			if err != nil {
				t.Skipf("%s unavailable for harmless toggle oracle", name)
			}
			home := t.TempDir()
			script := filepath.Join(home, "script")
			if err := os.WriteFile(script, []byte("printf guardclaw-toggle-oracle"), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(shell, "-n", "+n", script)
			cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
			out, err := cmd.Output()
			if err != nil || string(out) != "guardclaw-toggle-oracle" {
				t.Fatalf("native %s -n +n did not execute fixed marker: output=%q err=%v", name, out, err)
			}
		})
	}
}

func TestNormalizedCommandViewRetainsRegexChecks(t *testing.T) {
	if result := CheckCommandInjectionNormalized("ｅｃｈｏ ok ＆＆ pwd"); !result.Detected {
		t.Fatal("normalized regex command chaining was lost")
	}
}
