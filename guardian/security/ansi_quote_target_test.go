// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import "testing"

func TestANSIQuotedGuardTargets(t *testing.T) {
	for _, command := range []string{
		`systemctl stop $'\x67uardclaw'`,
		`systemctl stop $'\147uardclaw'`,
		`systemctl stop $'\u0067uardclaw'`,
		`systemctl stop $'\U00000067uardclaw'`,
		`systemctl stop $'guard\0ignored'claw`,
		`systemctl stop $'guard\u0000ignored'claw`,
		`systemctl stop $'guard\400ignored'claw`,
		`systemctl stop $'\u67uardclaw'`,
		`sh -c "systemctl stop \$'\u0067uardclaw'"`,
	} {
		if _, ok := MatchSelfProtection(command); !ok {
			t.Errorf("guard target %q not detected", command)
		}
		if !CheckCommandInjection(command).Detected || !CheckAgentCommand(command).Detected {
			t.Errorf("guard target %q admitted by a command checker", command)
		}
	}
	for _, command := range []string{`systemctl status $'nginx'`, `systemctl stop $'ng\u0069nx'`, `printf $'line\nnext'`} {
		if _, ok := MatchSelfProtection(command); ok {
			t.Errorf("ordinary command %q detected", command)
		}
	}
	if !CheckAgentCommand(`$'\u006c's -la`).Detected {
		t.Fatal("decoding made an encoded command name admissible")
	}
}

func TestANSIQuotedWordSemantics(t *testing.T) {
	for _, example := range []struct{ input, word string }{
		{`echo foo$'\u0062'ar`, "foobar"},
		{`echo $'a\0hidden'b`, "ab"},
		{`echo $'a\x00hidden'b`, "ab"},
		{`echo $'\q'`, `\q`},
		{`echo $'\x'`, `\x`},
		{`echo $'line\nnext'`, "line\nnext"},
		{`echo $'quote\'text'`, "quote'text"},
	} {
		parser := &shParser{s: example.input}
		commands := parser.parseList(0)
		if parser.overflow || len(commands) != 1 || len(commands[0].words) != 2 || commands[0].words[1].text != example.word {
			t.Errorf("parse %q = %#v, want word %q", example.input, commands, example.word)
		}
	}
}
