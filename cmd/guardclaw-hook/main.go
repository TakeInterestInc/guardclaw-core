// Copyright 2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

// Command guardclaw-hook is an offline Claude Code command-hook adapter and
// receipt verifier. Preview never writes configuration; there is no installer.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/TakeInterestInc/guardclaw-core/guardian/claudehooks"
	"github.com/TakeInterestInc/guardclaw-core/guardian/receipts"
)

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func run(args []string, in io.Reader, out, stderr io.Writer) int {
	fs := flag.NewFlagSet("guardclaw-hook", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyPath := fs.String("policy", "", "absolute personal policy JSON path")
	journal := fs.String("receipts", "", "absolute private journal path; parent must exist")
	preview := fs.Bool("preview", false, "print a Claude settings fragment; writes nothing")
	binary := fs.String("binary", "", "absolute binary path for preview")
	check := fs.Bool("check-policy", false, "validate policy only; writes nothing")
	verify := fs.Bool("verify", false, "verify journal and print a checkpoint; writes nothing")
	checkpoint := fs.String("checkpoint", "", "trusted checkpoint JSON file for verification")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2
	}
	fail := func(text string) int { fmt.Fprintln(stderr, "GuardClaw:", text); return 2 }
	if *verify {
		f, err := os.Open(*journal)
		if err != nil {
			return fail("cannot read receipt journal")
		}
		defer f.Close()
		var expected *receipts.Checkpoint
		if *checkpoint != "" {
			b, err := os.ReadFile(*checkpoint)
			if err != nil {
				return fail("cannot read trusted checkpoint")
			}
			expected = &receipts.Checkpoint{}
			d := json.NewDecoder(strings.NewReader(string(b)))
			d.DisallowUnknownFields()
			if err := d.Decode(expected); err != nil {
				return fail("invalid trusted checkpoint")
			}
			var extra any
			if err := d.Decode(&extra); err != io.EOF {
				return fail("trailing checkpoint data")
			}
		}
		tip, err := receipts.Verify(f, expected)
		if err != nil {
			return fail(err.Error())
		}
		if err := json.NewEncoder(out).Encode(tip); err != nil {
			return fail("output unavailable")
		}
		return 0
	}
	if !filepath.IsAbs(*policyPath) {
		return fail("--policy must be absolute")
	}
	p, err := claudehooks.LoadPolicy(*policyPath)
	if err != nil {
		return fail(err.Error())
	}
	if *check {
		fmt.Fprintln(out, "personal policy valid (exact tool names; no host configuration changed)")
		return 0
	}
	if !filepath.IsAbs(*journal) {
		return fail("--receipts must be absolute")
	}
	if *preview {
		if !filepath.IsAbs(*binary) || strings.ContainsAny(*binary+*policyPath+*journal, "\n\r\x00") {
			return fail("preview needs absolute --binary and paths without control characters")
		}
		cmd := quote(*binary) + " --policy " + quote(*policyPath) + " --receipts " + quote(*journal)
		hooks := map[string]any{}
		for _, event := range []string{"PreToolUse", "PostToolUse", "PostToolUseFailure"} {
			hooks[event] = []any{map[string]any{"matcher": "*", "hooks": []any{map[string]any{"type": "command", "command": cmd, "timeout": 10}}}}
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{"hooks": hooks}); err != nil {
			return fail("output unavailable")
		}
		return 0
	}
	e, err := claudehooks.Decode(in)
	if err != nil {
		return fail(err.Error())
	}
	executable, _ := os.Executable()
	if err := claudehooks.Handle(e, p, *journal, []string{*policyPath, *journal, executable}, out); err != nil {
		return fail(err.Error())
	}
	return 0
}
func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }
