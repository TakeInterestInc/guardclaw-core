// Copyright 2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0
package claudehooks

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TakeInterestInc/guardclaw-core/guardian/policy"
	"github.com/TakeInterestInc/guardclaw-core/guardian/receipts"
)

func TestSyntheticPolicyAndReceiptBoundary(t *testing.T) {
	p := policy.Policy{Version: 1, Default: "ask", Tools: map[string]string{"Read": "allow", "Bash": "allow", "mcp__example__send_email": "ask", "mcp__example__delete": "deny", "mcp__example__lookup": "allow"}}
	cases := []struct {
		tool   string
		args   map[string]any
		want   string
		reason string
	}{
		{"mcp__example__send_email", map[string]any{"to": "synthetic@example.invalid", "body": "only a test"}, "ask", "personal_policy"},
		{"mcp__example__delete", map[string]any{"id": "synthetic"}, "deny", "personal_policy"},
		{"mcp__example__lookup", map[string]any{"query": "synthetic"}, "allow", "personal_policy"},
		{"mcp__unknown__send", map[string]any{}, "ask", "personal_policy"},
		{"Bash", map[string]any{"command": "go test ./..."}, "ask", "shell_review"},
		{"Bash", map[string]any{"command": "rm -rf /"}, "deny", "command_pattern"},
		{"Bash", map[string]any{"command": 1}, "deny", "invalid_tool_input"},
		{"Read", map[string]any{"file_path": "/etc/shadow"}, "deny", "protected_path"},
	}
	journal := filepath.Join(t.TempDir(), "journal")
	for i, c := range cases {
		e := Input{Event: "PreToolUse", Session: "test-session", ToolUse: string(rune('a' + i)), Tool: c.tool, CWD: t.TempDir(), Arguments: c.args}
		var out bytes.Buffer
		if err := Handle(e, p, journal, nil, &out); err != nil {
			t.Fatal(err)
		}
		var response map[string]any
		if err := json.Unmarshal(out.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if c.want == "allow" {
			if _, ok := response["hookSpecificOutput"]; ok {
				t.Fatal("allow must never skip host approval")
			}
		} else {
			decision := response["hookSpecificOutput"].(map[string]any)["permissionDecision"]
			if decision != c.want {
				t.Fatalf("want %s got %v", c.want, decision)
			}
		}
		got := Check(e, p, nil)
		if got.Decision != c.want || got.Rule != c.reason {
			t.Fatalf("%+v", got)
		}
	}
	f, _ := os.Open(journal)
	defer f.Close()
	tip, err := receipts.Verify(f, nil)
	if err != nil || tip.Sequence != uint64(len(cases)) {
		t.Fatalf("tip=%+v err=%v", tip, err)
	}
}
func TestRedactionBeforePersistenceAndCompletion(t *testing.T) {
	secret := "test-only-token-never-persist-this"
	journal := filepath.Join(t.TempDir(), "journal")
	p := policy.Policy{Version: 1, Default: "ask", Tools: map[string]string{"mcp__example__send_email": "ask"}}
	raw := `{"hook_event_name":"PreToolUse","session_id":"synthetic-session","tool_use_id":"synthetic-tool-use","tool_name":"mcp__example__send_email","tool_input":{"token":"` + secret + `","to":"synthetic@example.invalid","body":"private test body"},"cwd":"/synthetic/path"}`
	e, err := Decode(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Handle(e, p, journal, nil, &out); err != nil {
		t.Fatal(err)
	}
	e.Event = "PostToolUse"
	if err := Handle(e, p, journal, nil, &out); err != nil {
		t.Fatal(err)
	}
	e.Event = "PostToolUseFailure"
	if err := Handle(e, p, journal, nil, &out); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(journal)
	h := sha256.Sum256([]byte(secret))
	args, _ := json.Marshal(e.Arguments)
	argHash := sha256.Sum256(args)
	for _, s := range []string{secret, "synthetic@example.invalid", "private test body", "/synthetic/path", "synthetic-session", hex.EncodeToString(h[:]), hex.EncodeToString(argHash[:])} {
		if bytes.Contains(data, []byte(s)) {
			t.Fatalf("persisted sensitive input or digest %q", s)
		}
	}
	var rows []receipts.Record
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var r receipts.Record
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, r)
	}
	if rows[0].ActionID != rows[1].ActionID || rows[2].Outcome != "failure" || rows[1].Outcome != "success" {
		t.Fatal("completion observation mismatch")
	}
	if rows[0].Decision != "ask" || rows[1].Decision != "none" {
		t.Fatal("ask is not proof of human approval")
	}
	e.Tool = secret
	if err := Handle(e, p, journal, nil, &out); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(journal)
	if bytes.Contains(data, []byte(secret)) {
		t.Fatal("unknown tool leaked")
	}
}
func TestFailureAndDirectAdapterPathProtection(t *testing.T) {
	dir := t.TempDir()
	owned := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(owned, []byte("policy"), 0600); err != nil {
		t.Fatal(err)
	}
	e := Input{Event: "PreToolUse", Tool: "Write", CWD: dir, Arguments: map[string]any{"file_path": owned}}
	p := policy.Policy{Default: "allow", Tools: map[string]string{"Write": "allow"}}
	if v := Check(e, p, []string{owned}); v.Decision != "deny" {
		t.Fatal("own policy writable")
	}
	alias := filepath.Join(dir, "alias.json")
	if err := os.Link(owned, alias); err != nil {
		t.Fatal(err)
	}
	e.Arguments["file_path"] = alias
	if v := Check(e, p, []string{owned}); v.Decision != "deny" {
		t.Fatal("direct file tool ignored same-file alias")
	}
	var out bytes.Buffer
	if err := Handle(e, p, filepath.Join(dir, "missing", "journal"), nil, &out); err == nil || out.Len() != 0 {
		t.Fatal("failed persistence produced permission")
	}
	if err := os.WriteFile(filepath.Join(dir, "journal"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Handle(e, p, filepath.Join(dir, "journal"), nil, &out); err == nil {
		t.Fatal("allowed after partial receipt")
	}
	for _, input := range []string{`{}`, `{"hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{}}`, `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":[]}`, strings.Repeat("x", (1<<20)+1)} {
		if _, err := Decode(strings.NewReader(input)); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
}

func TestOpaqueShellIsNeverAutomaticallyAllowed(t *testing.T) {
	p := policy.Policy{Version: 1, Default: "allow", Tools: map[string]string{"Bash": "allow"}}
	for _, command := range []string{`cd "$HOME" && rm -rf Documents`, `S="$HOME/go/bin/guardclaw-scan"; cp ./fake "$S"`, `python script.py`} {
		v := Check(Input{Tool: "Bash", Arguments: map[string]any{"command": command}}, p, nil)
		if v.Decision != "deny" && v.Decision != "ask" {
			t.Fatalf("opaque shell autoallowed: %+v", v)
		}
	}
}
