// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import "strings"

// Agent mode.
//
// CheckCommandInjection is strict: command chaining (`&&`, `;`, `|`, `&`) and
// substitution (`$( )`, backticks) deny on their own, which is right for
// untrusted input and wrong for a coding agent, which runs `cd src && npm
// test` and `echo $(date)` all day. CheckAgentCommand keeps every
// non-structural rule and replaces the structural ones with a look inside:
// the command is split the way a shell would split it (the self-protection
// parser), wrappers are opened (sh -c, eval, su -c, watch, xargs, find
// -exec, sudo, env, nice and the rest), and each simple command is judged on
// its own. CheckCommandInjection is unchanged and stays the strict default.

// agentStructural are the categories that do not deny on their own in agent
// mode: they describe how commands are joined, not what they do.
var agentStructural = map[CommandInjectionCategory]bool{
	CmdCategoryChaining:     true,
	CmdCategorySubstitution: true,
}

// agentDenyCategories deny on any match.
var agentDenyCategories = map[CommandInjectionCategory]bool{
	CmdCategoryDestructive: true,
	CmdCategoryPipe:        true,
	CmdCategoryExfil:       true,
}

// agentExempt are patterns agent mode replaces with a precise check:
// rm_rf_dot (`rm\s+-rf\s+\.` also matches `rm -rf ./build`) by
// agentRmVerdict, pipe_xargs by opening xargs as a wrapper, and pipe_tee
// (`npm test | tee log.txt`), whose write target the caller's own path
// rules judge.
var agentExempt = map[string]bool{
	"rm_rf_dot":  true,
	"pipe_xargs": true,
	"pipe_tee":   true,
}

// agentStillDeny are structural patterns that stay denials: a substitution
// whose content is a download runs whatever the server sends.
var agentStillDeny = map[string]bool{
	"subst_curl":    true,
	"subst_wget":    true,
	"backtick_curl": true,
}

// CheckAgentCommand judges one shell command for an AI coding agent. It
// denies what CheckCommandInjection denies except the structural categories,
// and it denies any simple command inside the line (after splitting and
// opening wrappers) that a deny rule matches.
func CheckAgentCommand(input string) *CommandInjectionResult {
	none := &CommandInjectionResult{}
	if input == "" {
		return none
	}
	for _, s := range []string{input, NormalizeInput(input)} {
		if r := agentPatternMatch(s); r != nil {
			return r
		}
		if name, ok := MatchSelfProtection(s); ok {
			return agentResult(name, CmdCategoryDestructive, 1.0)
		}
	}
	p := &shParser{s: input}
	cmds := p.parseList(0)
	if p.overflow {
		return agentResult("agent_nesting_too_deep", CmdCategorySubstitution, 1.0)
	}
	w := &agentWalker{}
	if r := w.list(cmds); r != nil {
		return r
	}
	return none
}

func agentResult(name string, category CommandInjectionCategory, score float64) *CommandInjectionResult {
	return &CommandInjectionResult{
		Detected:    true,
		Score:       score,
		Confidence:  score,
		Category:    category,
		PatternName: name,
		Reason:      "Command injection detected (agent mode): " + name,
	}
}

// agentPatternMatch runs every pattern (not only the best one, since a
// structural match can outrank a real one) and returns the strongest that
// denies in agent mode.
func agentPatternMatch(s string) *CommandInjectionResult {
	var best *CommandInjectionPattern
	for i := range CommandInjectionPatterns {
		pat := &CommandInjectionPatterns[i]
		if agentExempt[pat.Name] {
			continue
		}
		denies := agentStillDeny[pat.Name] ||
			agentDenyCategories[pat.Category] ||
			(pat.Severity >= 1.0 && !agentStructural[pat.Category])
		if !denies || !pat.Pattern.MatchString(s) {
			continue
		}
		if best == nil || pat.Severity > best.Severity {
			best = pat
		}
	}
	if best == nil {
		return nil
	}
	r := agentResult(best.Name, best.Category, best.Severity)
	r.MatchedPattern = best.Pattern.String()
	return r
}

type agentWalker struct {
	depth int
}

func (w *agentWalker) script(s string) *CommandInjectionResult {
	if w.depth >= shMaxDepth {
		return agentResult("agent_nesting_too_deep", CmdCategorySubstitution, 1.0)
	}
	w.depth++
	defer func() { w.depth-- }()
	if r := agentPatternMatch(s); r != nil {
		return r
	}
	p := &shParser{s: s}
	cmds := p.parseList(0)
	if p.overflow {
		return agentResult("agent_nesting_too_deep", CmdCategorySubstitution, 1.0)
	}
	return w.list(cmds)
}

func (w *agentWalker) list(cmds []shCmd) *CommandInjectionResult {
	for _, c := range cmds {
		for _, word := range c.words {
			for _, sub := range word.subs {
				if r := w.list(sub); r != nil {
					return r
				}
			}
		}
		if r := w.command(c.words); r != nil {
			return r
		}
	}
	return nil
}

var agentShells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "ash": true, "fish": true, "csh": true, "tcsh": true}

func agentIsInterpreter(name string) bool {
	if agentShells[name] {
		return true
	}
	for _, p := range []string{"python", "perl", "ruby", "node", "php", "osascript", "lua"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// command judges one simple command: its text with wrappers removed and
// quotes resolved, the precise rm check, and the commands it wraps.
func (w *agentWalker) command(words []shWord) *CommandInjectionResult {
	name, args, _ := splitCommand(words)
	if name == "" {
		return nil
	}
	if r := agentPatternMatch(strings.TrimSpace(name + " " + wordTexts(args))); r != nil {
		return r
	}
	if r := agentRmVerdict(name, args); r != nil {
		return r
	}
	switch {
	case agentShells[name] || name == "su":
		if s, ok := shellScriptArg(args); ok {
			return w.script(s)
		}
	case name == "eval":
		return w.script(wordTexts(args))
	case name == "watch":
		return w.script(wordTexts(skipOptions(args, "nd")))
	case name == "xargs":
		rest := skipOptions(args, "aEeILlnPsd")
		if len(rest) == 0 {
			return nil
		}
		if inner, _, _ := splitCommand(rest); agentIsInterpreter(inner) {
			return agentResult("pipe_xargs_shell", CmdCategoryPipe, 1.0)
		}
		return w.command(rest)
	case name == "find":
		return w.find(args)
	}
	return nil
}

// agentDangerousTarget is a path whose recursive removal is never a build
// step: the root, a home folder or anything at its top, the working folder
// or its parent, a bare glob, or a top-level system folder.
func agentDangerousTarget(t string) bool {
	t = strings.TrimSpace(t)
	if t == "" {
		return false
	}
	trimmed := strings.TrimRight(t, "/")
	switch trimmed {
	case "", ".", "..", "*", ".*", "./*", "../*", "/*", "~", "~/*", "$HOME", "${HOME}", "$HOME/*", "${HOME}/*":
		return true
	}
	if strings.HasPrefix(t, "~/") || strings.HasPrefix(t, "$HOME/") || strings.HasPrefix(t, "${HOME}/") {
		rest := t[strings.IndexByte(t, '/')+1:]
		rest = strings.TrimRight(rest, "/")
		// ~/x (a folder at the top of home) and anything in a dot folder or Library.
		if !strings.Contains(rest, "/") || strings.HasPrefix(rest, ".") || strings.HasPrefix(rest, "Library") {
			return true
		}
	}
	if strings.HasPrefix(trimmed, "/") && strings.Count(trimmed, "/") == 1 {
		return true // /usr, /etc, /Users, ...
	}
	if (strings.HasPrefix(trimmed, "/Users/") || strings.HasPrefix(trimmed, "/home/")) && strings.Count(trimmed, "/") <= 3 {
		return true // a home folder or a folder at its top
	}
	return false
}

// agentRmVerdict replaces rm_rf_dot: a recursive rm denies when a target is
// `.`, `./`, `..`, `*`, `~`, `/` or a variant, never `./build` or `dist/`.
// rm_rf_root and rm_rf_home still run as patterns.
func agentRmVerdict(name string, args []shWord) *CommandInjectionResult {
	if name != "rm" {
		return nil
	}
	recursive := false
	var targets []string
	endOfFlags := false
	for _, a := range args {
		t := a.text
		switch {
		case !endOfFlags && t == "--":
			endOfFlags = true
		case !endOfFlags && (t == "--recursive" || t == "-R"):
			recursive = true
		case !endOfFlags && strings.HasPrefix(t, "--"):
		case !endOfFlags && strings.HasPrefix(t, "-") && len(t) > 1:
			if strings.ContainsAny(t[1:], "rR") {
				recursive = true
			}
		default:
			targets = append(targets, t)
		}
	}
	if !recursive {
		return nil
	}
	for _, t := range targets {
		if agentDangerousTarget(t) {
			return agentResult("rm_rf_dot", CmdCategoryDestructive, 1.0)
		}
	}
	return nil
}

var findFilters = map[string]bool{"-name": true, "-iname": true, "-path": true, "-ipath": true, "-regex": true, "-iregex": true, "-newer": true, "-mtime": true, "-mmin": true, "-size": true, "-user": true, "-wholename": true}

// find opens -exec, -execdir, -ok and -okdir as wrappers, and denies a
// delete or an exec'd rm, shred or unlink over a start path that is never a
// build folder (or over `.` with nothing to narrow it).
func (w *agentWalker) find(args []shWord) *CommandInjectionResult {
	var starts []string
	i := 0
	for ; i < len(args); i++ {
		t := args[i].text
		if strings.HasPrefix(t, "-") || t == "(" || t == "!" {
			break
		}
		starts = append(starts, t)
	}
	filtered := false
	deletes := false
	for ; i < len(args); i++ {
		t := args[i].text
		if findFilters[t] {
			filtered = true
		}
		if t == "-delete" {
			deletes = true
		}
		if t != "-exec" && t != "-execdir" && t != "-ok" && t != "-okdir" {
			continue
		}
		j := i + 1
		for j < len(args) && args[j].text != ";" && args[j].text != "+" {
			j++
		}
		inner := args[i+1 : j]
		i = j
		if len(inner) == 0 {
			continue
		}
		innerName, _, _ := splitCommand(inner)
		if innerName == "rm" || innerName == "shred" || innerName == "unlink" {
			deletes = true
		}
		if r := w.command(inner); r != nil {
			return r
		}
	}
	if !deletes {
		return nil
	}
	if len(starts) == 0 {
		starts = []string{"."}
	}
	for _, s := range starts {
		trimmed := strings.TrimRight(s, "/")
		isHere := trimmed == "." || trimmed == ".."
		if isHere && filtered {
			continue
		}
		if agentDangerousTarget(s) {
			return agentResult("find_exec_destructive", CmdCategoryDestructive, 1.0)
		}
	}
	return nil
}
