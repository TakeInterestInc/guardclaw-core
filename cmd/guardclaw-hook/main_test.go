// Copyright 2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreviewAndOfflineSyntheticHook(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.json")
	journal := filepath.Join(dir, "receipts.jsonl")
	if err := os.WriteFile(policy, []byte(`{"version":1,"default":"ask","tools":{"mcp__example__send_email":"ask"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--policy", policy, "--receipts", journal}
	var out, errout bytes.Buffer
	if code := run(append(args, "--preview", "--binary", "/synthetic/a' b/guardclaw-hook"), strings.NewReader(""), &out, &errout); code != 0 {
		t.Fatalf("%d %s", code, errout.String())
	}
	var fragment map[string]any
	if err := json.Unmarshal(out.Bytes(), &fragment); err != nil {
		t.Fatal(err)
	}
	if len(fragment["hooks"].(map[string]any)) != 3 {
		t.Fatal("missing events")
	}
	if _, err := os.Stat(journal); !os.IsNotExist(err) {
		t.Fatal("preview wrote journal")
	}
	out.Reset()
	errout.Reset()
	raw := `{"hook_event_name":"PreToolUse","tool_name":"mcp__example__send_email","tool_input":{"to":"synthetic@example.invalid","body":"test only"},"session_id":"synthetic","tool_use_id":"synthetic"}`
	if code := run(args, strings.NewReader(raw), &out, &errout); code != 0 || !strings.Contains(out.String(), `"permissionDecision":"ask"`) {
		t.Fatalf("%d %s %s", code, out.String(), errout.String())
	}
	out.Reset()
	errout.Reset()
	if code := run([]string{"--verify", "--receipts", journal}, strings.NewReader(""), &out, &errout); code != 0 {
		t.Fatalf("%d %s", code, errout.String())
	}
	anchor := filepath.Join(dir, "anchor.json")
	if err := os.WriteFile(anchor, out.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journal, nil, 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errout.Reset()
	if code := run([]string{"--verify", "--receipts", journal, "--checkpoint", anchor}, strings.NewReader(""), &out, &errout); code != 2 {
		t.Fatal("missing trusted anchor accepted")
	}
	out.Reset()
	errout.Reset()
	if code := run(args, strings.NewReader("invalid"), &out, &errout); code != 2 {
		t.Fatal("invalid hook did not block")
	}
	if strings.Contains(errout.String(), "invalid\n") {
		t.Fatal("input copied to failure")
	}
}
