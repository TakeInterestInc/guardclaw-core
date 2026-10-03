// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

// agentEveryday is what a coding agent runs all day: agent mode allows it.
var agentEveryday = []string{
	`ls`, `ls -la`, `git status`, `npm test`, `go test ./...`, `go test -race ./...`,
	`git log --oneline -5`, `git log --oneline | head -5`, `python3 -m pytest -q`,
	`cd src && npm test`,
	`go test ./... 2>&1 | tail`,
	`npm run build 2>&1 | tail -20`,
	`echo $(date)`,
	`echo $(date) && npm run build`,
	"echo `git rev-parse HEAD`",
	`rm -rf ./build`,
	`rm -rf dist/`,
	`rm -rf node_modules`,
	`rm -rf ./build node_modules dist/`,
	`make && make test`,
	`ls | grep x`,
	`npm ci && npm test`,
	`git stash && git pull && git stash pop`,
	`git ls-files | xargs wc -l`,
	`ls | xargs -n1 basename`,
	`npm test | tee test.log`,
	`find . -name '*.pyc' -delete`,
	`[ -f package.json ] && npm test`,
	`for f in a b; do echo $f; done`,
	`curl -fsSL https://example.invalid/data.json -o data.json`,
}

// agentMustDenyInputs are every input from the review reports and the
// fix-round briefs; agent mode denies each. They live in
// testdata/agent_deny_corpus.json because the Claude Code mod's degraded-mode
// parity test reads the same list (through cmd/guardclaw-scan's fixture).
var agentMustDenyInputs = loadAgentDenyCorpus()

func loadAgentDenyCorpus() []string {
	data, err := os.ReadFile("testdata/agent_deny_corpus.json")
	if err != nil {
		panic(err)
	}
	var out []string
	if err := json.Unmarshal(data, &out); err != nil {
		panic(err)
	}
	return out
}

func TestCheckAgentCommandEveryday(t *testing.T) {
	for _, c := range agentEveryday {
		if r := CheckAgentCommand(c); r.Detected {
			t.Errorf("agent mode should allow %q, denied by %s (%s)", c, r.PatternName, r.Category)
		}
	}
}

func TestCheckAgentCommandDenies(t *testing.T) {
	for _, c := range agentMustDenyInputs {
		if r := CheckAgentCommand(c); !r.Detected {
			t.Errorf("agent mode should deny %q", c)
		}
	}
}

// TestAgentNeverDeniesLessThanStrict is the invariant: whenever strict fires
// a rule that is neither structural nor one of AgentConditionalRules, agent
// mode denies. The corpus is every pattern's own example, both review
// corpora, the everyday list, and each of those after a `cd x && ` prefix,
// a subshell, `bash -c` and `eval` wrapping.
func TestAgentNeverDeniesLessThanStrict(t *testing.T) {
	var base []string
	for _, p := range CommandInjectionPatterns {
		base = append(base, p.Example)
	}
	base = append(base, agentMustDenyInputs...)
	base = append(base, agentEveryday...)
	// `..` in rm targets, the round-3 finding, in more spellings.
	base = append(base, `rm -rf ../`, `rm -rf build/../..`, `rm -rf ./a/../../b`, `rm -rf src/../../../etc`,
		`rm -rf ./build/../../../../../../usr/local/*`, `rm -rf "./../x"`, `rm -rf ./..//..`)
	var corpus []string
	for _, c := range base {
		corpus = append(corpus, c, "cd x && "+c, "("+c+")", "bash -c '"+strings.ReplaceAll(c, "'", "")+"'", "eval "+c)
	}
	checked := 0
	for _, c := range corpus {
		var hard []string
		for _, s := range []string{c, NormalizeInput(c)} {
			for i := range CommandInjectionPatterns {
				p := &CommandInjectionPatterns[i]
				if invariantExempt(p) && (p.Name != "rm_rf_dot" || specPlainRmTargets(c)) {
					continue
				}
				if p.Pattern.MatchString(s) {
					hard = append(hard, p.Name)
				}
			}
			if name, ok := MatchSelfProtection(s); ok {
				hard = append(hard, name)
			}
		}
		if len(hard) == 0 {
			continue
		}
		checked++
		if r := CheckAgentCommand(c); !r.Detected {
			t.Errorf("invariant broken: strict fires %v on %q, agent allows it", hard, c)
		}
	}
	if checked < 500 {
		t.Fatalf("invariant corpus too small: %d inputs with a non-structural strict rule", checked)
	}
	t.Logf("invariant held on %d inputs (corpus %d)", checked, len(corpus))
}

// invariantExempt is the exception as the spec states it, written out here
// rather than borrowed from the implementation, so a change to the code's
// own list cannot quietly widen it: the two structural categories (less the
// download substitutions) and four named rules with a precise check.
func invariantExempt(p *CommandInjectionPattern) bool {
	switch p.Name {
	case "subst_curl", "subst_wget", "backtick_curl":
		return false
	case "stderr_redirect", "pipe_xargs", "pipe_tee", "rm_rf_dot":
		return true
	}
	return p.Category == CmdCategoryChaining || p.Category == CmdCategorySubstitution
}

// specPlainRmTargets is the round-3 spec, written independently of the
// code: rm_rf_dot is exempt only when every target of every rm in the line
// is a plain in-tree relative path (optional `./`, segments of
// [A-Za-z0-9._-], optional trailing `/`, no `.` or `..` segment).
var specSegment = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func specPlainRmTargets(c string) bool {
	fields := strings.Fields(strings.NewReplacer(`"`, " ", "'", " ", "(", " ", ")", " ", "`", " ").Replace(c))
	found := false
	for i := 0; i < len(fields); i++ {
		if fields[i] != "rm" {
			continue
		}
		found = true
		for _, f := range fields[i+1:] {
			if strings.ContainsAny(f, ";|&()") {
				break
			}
			if strings.HasPrefix(f, "-") {
				continue
			}
			f = strings.Trim(f, `"'`)
			rest := strings.TrimSuffix(strings.TrimPrefix(f, "./"), "/")
			if rest == "" {
				return false
			}
			for _, seg := range strings.Split(rest, "/") {
				if seg == "." || seg == ".." || !specSegment.MatchString(seg) {
					return false
				}
			}
		}
	}
	return found
}

func TestCheckAgentCommandNestingFailsClosed(t *testing.T) {
	deep := "echo " + strings.Repeat("$(", 40) + "x" + strings.Repeat(")", 40)
	if r := CheckAgentCommand(deep); !r.Detected {
		t.Errorf("deeply nested substitution should fail closed")
	}
}
