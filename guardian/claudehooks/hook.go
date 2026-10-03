// Copyright 2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

// Package claudehooks implements only Claude Code command hooks. It must not
// be installed as a Codex hook: Codex does not enforce an ask verdict.
package claudehooks

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/TakeInterestInc/guardclaw-core/guardian/policy"
	"github.com/TakeInterestInc/guardclaw-core/guardian/receipts"
	"github.com/TakeInterestInc/guardclaw-core/guardian/security"
)

type Input struct {
	Event     string         `json:"hook_event_name"`
	Session   string         `json:"session_id"`
	ToolUse   string         `json:"tool_use_id"`
	Tool      string         `json:"tool_name"`
	CWD       string         `json:"cwd"`
	Arguments map[string]any `json:"tool_input"`
}
type Verdict struct{ Decision, Rule string }

func Decode(in io.Reader) (Input, error) {
	var e Input
	// The host carries additional fields (including output) which are ignored.
	data, err := io.ReadAll(io.LimitReader(in, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return e, errors.New("invalid or oversized hook input")
	}
	if err := json.Unmarshal(data, &e); err != nil {
		return e, errors.New("invalid hook JSON")
	}
	if e.Tool == "" || e.Arguments == nil {
		return e, errors.New("hook needs tool_name and tool_input object")
	}
	switch e.Event {
	case "PreToolUse", "PostToolUse", "PostToolUseFailure":
	default:
		return e, errors.New("unsupported Claude hook event")
	}
	return e, nil
}

func Check(e Input, p policy.Policy, protected []string) Verdict {
	v := Verdict{p.Check(e.Tool), "personal_policy"}
	// Exactly identified shell fields only. This detects known shell patterns;
	// it cannot infer arbitrary program effects, email sends or all filesystem IO.
	fields := []string{"command"}
	if len(e.Tool) >= 5 && e.Tool[:5] == "mcp__" {
		fields = []string{"command", "cmd", "script", "code"}
	}
	if e.Tool == "Bash" || e.Tool == "Monitor" || (len(e.Tool) >= 5 && e.Tool[:5] == "mcp__") {
		if e.Tool == "Bash" || e.Tool == "Monitor" {
			if _, ok := e.Arguments["command"].(string); !ok {
				return Verdict{"deny", "invalid_tool_input"}
			}
		}
		sawCommand := false
		for _, field := range fields {
			value, exists := e.Arguments[field]
			if !exists {
				continue
			}
			sawCommand = true
			command, ok := value.(string)
			if !ok {
				return Verdict{"deny", "invalid_tool_input"}
			}
			for _, text := range []string{command, security.NormalizeInput(command)} {
				if security.CheckAgentCommand(text).Detected {
					return Verdict{"deny", "command_pattern"}
				}
			}
		}
		// No lexical matcher proves arbitrary program effects safe. All shell
		// requests require the host's real approval boundary, even if personal
		// policy says allow. Pattern rules and personal deny can still block.
		if sawCommand && v.Decision == "allow" {
			v = Verdict{"ask", "shell_review"}
		}
	}
	field := ""
	switch e.Tool {
	case "Read", "Write", "Edit", "MultiEdit":
		field = "file_path"
	case "NotebookEdit":
		field = "notebook_path"
	}
	if field != "" {
		if !filepath.IsAbs(e.CWD) {
			return Verdict{"deny", "invalid_tool_input"}
		}
		path, ok := e.Arguments[field].(string)
		if !ok || path == "" {
			return Verdict{"deny", "invalid_tool_input"}
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(e.CWD, path)
		}
		checker := security.NewDefaultWithSystemProtectedPathChecker()
		if checker.IsProtectedOnDisk(path) {
			return Verdict{"deny", "protected_path"}
		}
		// Protect the adapter binary, policy and journal from direct file tools.
		// Shell scripts/interpreters or other host tools are not fully mediated.
		real, err := filepath.EvalSymlinks(path)
		if err != nil {
			real = filepath.Clean(path)
		}
		for _, own := range protected {
			resolved, err := filepath.EvalSymlinks(own)
			if err != nil {
				resolved = filepath.Clean(own)
			}
			pathInfo, pathErr := os.Stat(path)
			ownInfo, ownErr := os.Stat(own)
			if real == resolved || (pathErr == nil && ownErr == nil && os.SameFile(pathInfo, ownInfo)) {
				return Verdict{"deny", "adapter_path"}
			}
		}
	}
	return v
}

// Handle appends a durable receipt before reporting any pre-tool decision.
// Allow intentionally emits no permissionDecision, preserving native checks.
// Errors use exit 2 (Claude blocks PreToolUse); completion errors cannot undo IO.
func Handle(e Input, p policy.Policy, journal string, protected []string, out io.Writer) error {
	id, err := receipts.ActionID(e.Session, e.ToolUse)
	if err != nil {
		return err
	}
	r := receipts.Record{Host: "claude-code", Tool: p.ReceiptTool(e.Tool), ActionID: id}
	var v Verdict
	if e.Event == "PreToolUse" {
		v = Check(e, p, protected)
		r.Event, r.Decision, r.Rule, r.Outcome = "decision", v.Decision, v.Rule, "pending"
	} else {
		r.Event, r.Decision, r.Rule, r.Outcome = "completion", "none", "host_observation", "success"
		if e.Event == "PostToolUseFailure" {
			r.Outcome = "failure"
		}
	}
	if _, err := receipts.Append(journal, r); err != nil {
		return errors.New("receipt unavailable or invalid; no pre-tool permission granted")
	}
	output := map[string]any{}
	if e.Event == "PreToolUse" && v.Decision != "allow" {
		output["hookSpecificOutput"] = map[string]string{
			"hookEventName": "PreToolUse", "permissionDecision": v.Decision,
			"permissionDecisionReason": "GuardClaw: " + v.Rule + "; review the pending tool call in the host permission prompt.",
		}
	}
	return json.NewEncoder(out).Encode(output)
}

func LoadPolicy(path string) (policy.Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return policy.Policy{}, errors.New("personal policy unavailable")
	}
	defer f.Close()
	return policy.Load(f)
}
