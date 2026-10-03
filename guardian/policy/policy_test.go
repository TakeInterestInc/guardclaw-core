// Copyright 2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"strings"
	"testing"
)

func TestStrictPolicy(t *testing.T) {
	for _, s := range []string{`{"version":1,"default":"allow","tools":{}} garbage`, `{"version":2,"default":"ask","tools":{}}`, `{"version":1,"default":"approve","tools":{}}`, `{"version":1,"default":"ask","tools":{"mcp__.*":"ask"}}`, `{"version":1,"default":"ask","tools":{},"typo":true}`, `{"version":1,"default":"ask"}`} {
		if _, err := Load(strings.NewReader(s)); err == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	p, err := Load(strings.NewReader(`{"version":1,"default":"ask","tools":{"Read":"allow","mcp__example__send_email":"ask","mcp__example__delete":"deny"}}`))
	if err != nil || p.Check("Read") != "allow" || p.Check("mcp__example__send_email") != "ask" || p.Check("unknown") != "ask" || p.Check("mcp__example__delete") != "deny" {
		t.Fatalf("p=%+v err=%v", p, err)
	}
}
