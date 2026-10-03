// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

// Command guardclaw-scan is a pure, offline pattern-detection CLI for the
// guardclaw open core. It drives ONLY the tiered matcher (Bloom -> Aho-Corasick
// -> composite RE2 -> entropy), seeded from the static in-package pattern corpus.
//
// It makes no network calls, has no cloud/auth/billing/policy surface, and does
// not fetch any threat-intelligence feed. It reads files (or directories) and
// prints a readable risk report. Exit code is non-zero when any high/critical
// finding fires, so it composes into CI.
//
// With --stdin-command it instead reads ONE shell command from standard input
// and runs the command-injection checker on it (see runCommand). That is the
// mode the Claude Code mod in claude-code-mod/ calls for every shell command
// the model asks to run.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/TakeInterestInc/guardclaw-core/guardian/security"
	"github.com/TakeInterestInc/guardclaw-core/guardian/tiered"
)

// maxCommandBytes bounds what --stdin-command reads. A longer command is an
// incomplete scan (exit 2), never a partial one.
const maxCommandBytes = 1024 * 1024

// commandVerdict is the one JSON line --stdin-command prints.
type commandVerdict struct {
	Decision string  `json:"decision"` // "deny" or "allow"
	Rule     string  `json:"rule,omitempty"`
	Category string  `json:"category,omitempty"`
	Score    float64 `json:"score,omitempty"`
	Reason   string  `json:"reason,omitempty"`
}

// runCommand scans one command read from stdin with CheckCommandInjection,
// once as written and once after NormalizeInput (NFKC, homoglyph and
// zero-width folding), and denies when either pass detects. It returns 1 for a
// deny, 0 for an allow and 2 when the command could not be read whole.
//
// It deliberately does not use tiered.Engine.Scan: that engine is the general
// input scanner (prompt injection, path traversal, secrets) and denies
// ordinary commands such as `go test ./...` (triple_dot_traversal).
func runCommand(stdin io.Reader, stdout, stderr io.Writer) int {
	data, err := io.ReadAll(io.LimitReader(stdin, maxCommandBytes+1))
	if err != nil {
		fmt.Fprintln(stderr, "read stdin:", err)
		return 2
	}
	if len(data) > maxCommandBytes {
		fmt.Fprintf(stderr, "command longer than %d bytes; not scanned\n", maxCommandBytes)
		return 2
	}
	command := string(data)
	verdict := commandVerdict{Decision: "allow"}
	for _, input := range []string{command, security.NormalizeInput(command)} {
		r := security.CheckCommandInjection(input)
		if r.Detected {
			verdict = commandVerdict{
				Decision: "deny",
				Rule:     r.PatternName,
				Category: string(r.Category),
				Score:    r.Score,
				Reason:   r.Reason,
			}
			break
		}
	}
	line, err := json.Marshal(verdict)
	if err != nil {
		fmt.Fprintln(stderr, "encode verdict:", err)
		return 2
	}
	fmt.Fprintln(stdout, string(line))
	if verdict.Decision == "deny" {
		return 1
	}
	return 0
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default: // "info" or empty
		return 0
	}
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--stdin-command" {
		os.Exit(runCommand(os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run returns 2 for an incomplete scan or usage/setup error, 1 for a
// high/critical finding, and 0 for a completed scan without those findings.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: guardclaw-scan <file-or-dir> [more paths...]")
		fmt.Fprintln(stderr, "       guardclaw-scan --stdin-command < command.txt")
		return 2
	}

	// nil cfg => all defaults; the Bloom/AC/RE2/entropy cascade is seeded from
	// security.ExportAllPatterns() (the static corpus, no paid feed).
	eng, err := tiered.NewEngine(nil)
	if err != nil {
		fmt.Fprintln(stderr, "engine init:", err)
		return 2
	}
	if !eng.Ready() {
		fmt.Fprintln(stderr, "engine not ready")
		return 2
	}

	var totalFindings int
	highestRank := 0
	var scanErrors int

	// scanOne scans a file LINE BY LINE. The detection engine is calibrated for
	// per-input scanning (one agent tool-call / one line). Scanning a whole
	// multi-line file as a single blob produces false positives (e.g. the
	// command-chaining pattern fires on the newline between two safe commands),
	// so each non-blank, non-comment line is treated as its own input and
	// findings are reported with their line number.
	scanOne := func(p string) {
		f, rerr := os.Open(p)
		if rerr != nil {
			fmt.Fprintf(stderr, "skip %s: %v\n", p, rerr)
			scanErrors++
			return
		}
		defer f.Close()

		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		lineNo := 0
		fileFindings := 0
		for sc.Scan() {
			lineNo++
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			r := eng.Scan(line)
			if r.Decision == "allow" {
				continue
			}
			totalFindings++
			fileFindings++
			if rank := severityRank(r.Severity); rank > highestRank {
				highestRank = rank
			}
			fmt.Fprintf(stdout, "%s:%d  [%-8s] decision=%-8s tier=%d score=%.2f pattern=%s\n",
				p, lineNo, r.Severity, r.Decision, r.Tier, r.Score, r.PatternID)
			if r.Reason != "" {
				fmt.Fprintf(stdout, "    reason: %s\n", r.Reason)
			}
		}
		if err := sc.Err(); err != nil {
			fmt.Fprintf(stderr, "read %s: %v\n", p, err)
			scanErrors++
			return
		}
		if fileFindings == 0 {
			fmt.Fprintf(stdout, "%-55s OK - no patterns matched\n", p)
		}
	}

	for _, arg := range args {
		info, statErr := os.Stat(arg)
		if statErr != nil {
			fmt.Fprintf(stderr, "skip %s: %v\n", arg, statErr)
			scanErrors++
			continue
		}
		if info.IsDir() {
			walkErr := filepath.Walk(arg, func(path string, fi os.FileInfo, werr error) error {
				if werr != nil {
					fmt.Fprintf(stderr, "walk %s: %v\n", path, werr)
					scanErrors++
					return nil
				}
				if fi.IsDir() {
					return nil
				}
				scanOne(path)
				return nil
			})
			if walkErr != nil {
				fmt.Fprintf(stderr, "walk %s: %v\n", arg, walkErr)
				scanErrors++
			}
			continue
		}
		scanOne(arg)
	}

	fmt.Fprintf(stdout, "\n%d finding(s); highest severity rank=%d; scan errors=%d\n", totalFindings, highestRank, scanErrors)
	if scanErrors > 0 {
		return 2
	}
	if highestRank >= severityRank("high") {
		return 1
	}
	return 0
}
