// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"regexp"
	"strings"
)

// Agent mode.
//
// CheckCommandInjection is strict: command chaining (`&&`, `;`, `|`, `&`) and
// substitution (`$( )`, backticks) deny on their own, which is right for
// untrusted input and wrong for a coding agent, which runs `cd src && npm
// test` and `echo $(date)` all day.
//
// CheckAgentCommand is the strict verdict with one narrow exception, and the
// invariant is that it never denies less than strict outside that exception:
//
//   - every strict rule is run over the line (all matches, not only the best);
//   - a fired rule is set aside only when it is RELAXABLE: its category is
//     structural (chaining, substitution), it is the literal `2>&1`
//     (stderr_redirect, a file-descriptor copy that writes nowhere), or it is
//     pipe_xargs, pipe_tee or rm_rf_dot AND every xargs, tee or recursive rm
//     in the line is shown harmless by a precise check;
//   - any other fired rule denies, exactly as in strict;
//   - then each simple command inside the line (split the way a shell splits
//     it, wrappers opened: sh -c, eval, su -c, watch, xargs, find -exec, sudo,
//     env, nice, $( ), backticks) is held to the same rule, and a command
//     whose name cannot be read without running something (a variable, a
//     substitution, a glob, a $'..' escape, a function or alias the line
//     defines) is denied.
//
// TestAgentNeverDeniesLessThanStrict pins the invariant.

// agentStructural are the categories that describe how commands are joined,
// not what they do.
var agentStructural = map[CommandInjectionCategory]bool{
	CmdCategoryChaining:     true,
	CmdCategorySubstitution: true,
}

// agentStillDeny are structural patterns that stay denials: a substitution
// whose content is a download runs whatever the server sends.
var agentStillDeny = map[string]bool{
	"subst_curl":    true,
	"subst_wget":    true,
	"backtick_curl": true,
}

// AgentConditionalRules are the non-structural strict rules agent mode may
// set aside, each only when its precise check passes for the whole line.
var AgentConditionalRules = map[string]bool{
	"stderr_redirect": true, // the pattern is the literal 2>&1
	"pipe_xargs":      true,
	"pipe_tee":        true,
	"rm_rf_dot":       true,
}

// IsAgentStructural reports whether a strict rule is one agent mode may set
// aside on its own (a structural category, never a still-deny pattern).
func IsAgentStructural(p *CommandInjectionPattern) bool {
	return agentStructural[p.Category] && !agentStillDeny[p.Name]
}

// CheckAgentCommand judges one shell command for an AI coding agent. See the
// package comment above for the invariant.
func CheckAgentCommand(input string) *CommandInjectionResult {
	none := &CommandInjectionResult{}
	if input == "" {
		return none
	}
	w := &agentWalker{defined: definedNames(input), cwdChanged: agentChangesDirectory(input)}
	for _, s := range []string{input, NormalizeInput(input)} {
		if r := w.strictLine(s); r != nil {
			return r
		}
	}
	p := &shParser{s: input}
	cmds := p.parseList(0)
	if p.overflow {
		return agentResult("agent_nesting_too_deep", CmdCategorySubstitution, 1.0)
	}
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

type agentWalker struct {
	depth      int
	defined    map[string]bool // functions and aliases the line itself defines
	cwdChanged bool            // cwd-sensitive effects cannot be resolved by this API
}

// strictLine runs every strict rule and self-protection over s and returns
// the strongest fired rule that is not relaxable for s.
// Directory state and arbitrary expansions cannot be proved safe by this
// lexical API. Refuse explicit mutation when the command changes directory,
// and refuse expansion-bearing mutation operands. Build/test commands retain
// their existing behavior; callers still need host approval or a sandbox.
var agentDirectoryChange = regexp.MustCompile(`(?i)(?:^|[\s;&|()])(?:cd|pushd|popd|chroot)\b|\b(?:env|sudo)\b[^;&|\n]*(?:--chdir(?:=|\s)|-C(?:\S+|\s|$)|-D(?:\S+|\s|$))|\bfind\b[^;&|\n]*-execdir\b`)

func agentChangesDirectory(s string) bool {
	s = strings.NewReplacer("\"", "", "'", "", "\\", "").Replace(s)
	return agentDirectoryChange.MatchString(s)
}

var agentMutators = map[string]bool{
	"rm": true, "cp": true, "mv": true, "install": true, "ln": true,
	"chmod": true, "chown": true, "chflags": true, "xattr": true,
	"truncate": true, "shred": true, "unlink": true, "tee": true,
	"sed": true, "dd": true, "rsync": true,
}

func agentMutates(name string, args []shWord) bool {
	if name != "sed" {
		return agentMutators[name]
	}
	for _, a := range args {
		if strings.HasPrefix(a.text, "--in-place") || (strings.HasPrefix(a.text, "-") && !strings.HasPrefix(a.text, "--") && strings.Contains(a.text[1:], "i")) {
			return true
		}
	}
	return false
}

func (w *agentWalker) strictLine(s string) *CommandInjectionResult {
	if name, ok := MatchSelfProtection(s); ok {
		return agentResult(name, CmdCategoryDestructive, 1.0)
	}
	var parsed []shCmd
	isParsed := false
	var best *CommandInjectionPattern
	for i := range CommandInjectionPatterns {
		pat := &CommandInjectionPatterns[i]
		if !pat.Pattern.MatchString(s) {
			continue
		}
		if IsAgentStructural(pat) {
			continue
		}
		if AgentConditionalRules[pat.Name] {
			if !isParsed {
				p := &shParser{s: s}
				parsed = p.parseList(0)
				if p.overflow {
					parsed = nil
				}
				isParsed = true
			}
			if w.conditionHolds(pat.Name, s, parsed) {
				continue
			}
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

// conditionHolds is the precise check behind each conditional rule. It
// fails closed: a line whose xargs, tee or rm cannot be found (the regex
// matched something the parser does not see as that command) keeps the deny.
func (w *agentWalker) conditionHolds(rule, line string, cmds []shCmd) bool {
	switch rule {
	case "stderr_redirect":
		return true
	case "pipe_xargs":
		return everyCommand(cmds, "xargs", xargsIsPlain)
	case "pipe_tee":
		return everyCommand(cmds, "tee", teeIsPlain)
	case "rm_rf_dot":
		return everyCommand(cmds, "rm", func(args []shWord) bool { return rmTargetsHarmless(args) }) &&
			lexicalRmTargetsPlain(line)
	}
	return false
}

// everyCommand reports whether the line holds at least one command named
// name, at any depth, and ok holds for every one of them.
func everyCommand(cmds []shCmd, name string, ok func(args []shWord) bool) bool {
	found, all := 0, true
	visitCommands(cmds, 0, func(n string, args []shWord) {
		if n == "" && args == nil {
			all = false // nesting too deep to see: fail closed
			return
		}
		if n == name {
			found++
			if !ok(args) {
				all = false
			}
		}
	})
	return found > 0 && all
}

// visitCommands calls fn for every simple command, opening substitutions
// and the wrappers whose inner command is in the line itself.
func visitCommands(cmds []shCmd, depth int, fn func(name string, args []shWord)) {
	if depth > shMaxDepth {
		fn("", nil) // too deep: callers see an unnamed command and fail closed
		return
	}
	for _, c := range cmds {
		for _, word := range c.words {
			for _, sub := range word.subs {
				visitCommands(sub, depth+1, fn)
			}
		}
		visitWords(c.words, depth, fn)
	}
}

func visitWords(words []shWord, depth int, fn func(name string, args []shWord)) {
	name, args, _ := splitCommand(words)
	if name == "" {
		return
	}
	fn(name, args)
	for _, inner := range innerScripts(name, args) {
		p := &shParser{s: inner}
		cmds := p.parseList(0)
		if p.overflow {
			fn("", nil)
			continue
		}
		visitCommands(cmds, depth+1, fn)
	}
	for _, inner := range innerCommands(name, args) {
		visitWords(inner, depth+1, fn)
	}
}

// innerScripts are the strings a command runs as shell code.
func innerScripts(name string, args []shWord) []string {
	switch {
	case agentShells[name] || name == "su":
		if s, ok := shellScriptArg(args); ok {
			return []string{s}
		}
	case name == "eval":
		return []string{wordTexts(args)}
	case name == "watch":
		return []string{wordTexts(skipOptions(args, "nd"))}
	}
	return nil
}

// innerCommands are the commands xargs and find -exec run.
func innerCommands(name string, args []shWord) [][]shWord {
	switch name {
	case "xargs":
		if rest := skipOptions(args, "aEeILlnPsd"); len(rest) > 0 {
			return [][]shWord{rest}
		}
	case "find":
		var out [][]shWord
		for i := 0; i < len(args); i++ {
			t := args[i].text
			if t != "-exec" && t != "-execdir" && t != "-ok" && t != "-okdir" {
				continue
			}
			j := i + 1
			for j < len(args) && args[j].text != ";" && args[j].text != "+" {
				j++
			}
			if j > i+1 {
				out = append(out, args[i+1:j])
			}
			i = j
		}
		return out
	}
	return nil
}

var agentShells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "ash": true, "fish": true, "csh": true, "tcsh": true}

func agentIsInterpreter(name string) bool {
	if agentShells[name] {
		return true
	}
	for _, p := range []string{"python", "perl", "ruby", "node", "php", "osascript", "lua", "tclsh"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// xargsUnsafe are commands that, fed arguments from a pipe, can destroy,
// escalate, run code or reach the network.
var xargsUnsafe = map[string]bool{
	"rm": true, "shred": true, "unlink": true, "rmdir": true, "find": true, "mv": true, "cp": true,
	"dd": true, "truncate": true, "chmod": true, "chown": true, "chgrp": true, "ln": true,
	"kill": true, "pkill": true, "killall": true, "sudo": true, "doas": true, "su": true,
	"env": true, "eval": true, "exec": true, "xargs": true, "nohup": true, "nice": true,
	"timeout": true, "curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true,
	"socat": true, "scp": true, "rsync": true, "ssh": true, "sftp": true, "ftp": true,
	"tee": true, "git": true, "docker": true, "kubectl": true, "launchctl": true, "systemctl": true,
}

func xargsIsPlain(args []shWord) bool {
	rest := skipOptions(args, "aEeILlnPsd")
	if len(rest) == 0 {
		return true // bare xargs runs echo
	}
	i, _ := commandIndex(rest)
	if i >= len(rest) || !literalCommandWord(rest[i].text) {
		return false
	}
	name, _, _ := splitCommand(rest)
	return name != "" && !xargsUnsafe[name] && !agentIsInterpreter(name) && i == 0
}

// teeIsPlain: every file tee writes is a literal path inside the working
// folder (no leading / or ~, no .., no expansion).
func teeIsPlain(args []shWord) bool {
	for _, a := range args {
		t := a.text
		if strings.HasPrefix(t, "-") {
			continue
		}
		if t == "" || strings.ContainsAny(t, "$`") || strings.HasPrefix(t, "/") || strings.HasPrefix(t, "~") || strings.Contains(t, "..") {
			return false
		}
	}
	return true
}

// plainRelPath is a plain in-tree relative path: an optional leading `./`,
// then segments of [A-Za-z0-9._-] separated by `/`, an optional trailing `/`.
var plainRelPath = regexp.MustCompile(`^(?:\./)?[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*/?$`)

// rmTargetsHarmless: a non-recursive rm, or a recursive one whose every
// target is a plain in-tree relative path with no `.` or `..` segment (so no
// glob, no `~`, no `$`, no leading `/`). Anything else keeps strict's deny.
func rmTargetsHarmless(args []shWord) bool {
	recursive, targets := rmArgs(args)
	if !recursive {
		return true
	}
	if len(targets) == 0 {
		return false
	}
	for _, t := range targets {
		if !isPlainRelPath(t) {
			return false
		}
	}
	return true
}

// lexicalRmTargetsPlain reads the raw line as words, with quotes, parens and
// separators as breaks, and requires every word after an `rm` to be a flag
// or a plain relative path. It does not understand quoting on purpose: an rm
// the parser would read as inert (`eval bash -c 'rm -rf .'`) still has to
// look plain, so the exemption fails closed.
func lexicalRmTargetsPlain(line string) bool {
	words := strings.Fields(strings.Map(func(r rune) rune {
		if strings.ContainsRune("\"'`()", r) {
			return ' '
		}
		return r
	}, line))
	for i := 0; i < len(words); i++ {
		if words[i] != "rm" {
			continue
		}
		for _, f := range words[i+1:] {
			if strings.ContainsAny(f, ";|&") {
				break
			}
			if strings.HasPrefix(f, "-") {
				continue
			}
			if !isPlainRelPath(f) {
				return false
			}
		}
	}
	return true
}

func isPlainRelPath(t string) bool {
	if !plainRelPath.MatchString(t) {
		return false
	}
	rest := strings.TrimSuffix(strings.TrimPrefix(t, "./"), "/")
	if rest == "" {
		return false
	}
	for _, seg := range strings.Split(rest, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

func rmArgs(args []shWord) (bool, []string) {
	recursive := false
	var targets []string
	endOfFlags := false
	for _, a := range args {
		t := a.text
		switch {
		case !endOfFlags && t == "--":
			endOfFlags = true
		case !endOfFlags && t == "--recursive":
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
	return recursive, targets
}

// literalPath: no expansion the shell would do before rm sees it.
func literalPath(t string) bool {
	return !strings.ContainsAny(t, "$`")
}

// literalCommandWord: a command name readable without running anything.
// `[` and `[[` are the test command, not a glob.
func literalCommandWord(t string) bool {
	if t == "[" || t == "[[" {
		return true
	}
	if t == "" {
		return false
	}
	return !strings.ContainsAny(t, "$`?*[{")
}

var (
	funcDefRe  = regexp.MustCompile(`(?:^|[\s;&|(){}])(?:function\s+)?([A-Za-z_][A-Za-z0-9_.:-]*)\s*\(\s*\)`)
	funcKwRe   = regexp.MustCompile(`(?:^|[\s;&|(){}])function\s+([A-Za-z_][A-Za-z0-9_.:-]*)`)
	aliasDefRe = regexp.MustCompile(`(?:^|[\s;&|(){}])alias\s+([A-Za-z_][A-Za-z0-9_.:-]*)=`)
)

// definedNames are the shell functions and aliases the line defines; a later
// command by one of those names runs code this check did not read as a name.
func definedNames(s string) map[string]bool {
	out := map[string]bool{}
	for _, re := range []*regexp.Regexp{funcDefRe, funcKwRe, aliasDefRe} {
		for _, m := range re.FindAllStringSubmatch(s, -1) {
			out[strings.ToLower(m[1])] = true
		}
	}
	return out
}

func (w *agentWalker) script(s string) *CommandInjectionResult {
	if w.depth >= shMaxDepth {
		return agentResult("agent_nesting_too_deep", CmdCategorySubstitution, 1.0)
	}
	w.depth++
	defer func() { w.depth-- }()
	if r := w.strictLine(s); r != nil {
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

// command judges one simple command: its name must be readable, its text
// (wrappers removed, quotes resolved) is held to the strict rules, rm gets
// the precise check, and the commands it wraps are judged the same way.
func (w *agentWalker) command(words []shWord) *CommandInjectionResult {
	if w.depth > shMaxDepth {
		return agentResult("agent_nesting_too_deep", CmdCategorySubstitution, 1.0)
	}
	i, _ := commandIndex(words)
	if i >= len(words) {
		return nil
	}
	if !literalCommandWord(words[i].text) {
		return agentResult("agent_unevaluable_command", CmdCategoryEscape, 1.0)
	}
	name, args, _ := splitCommand(words)
	if agentMutates(name, args) {
		if w.cwdChanged {
			return agentResult("agent_cwd_mutation", CmdCategoryDestructive, 1.0)
		}
		for _, a := range args {
			if strings.ContainsAny(a.text, "$`*?{[") {
				return agentResult("agent_ambiguous_mutation", CmdCategoryDestructive, 1.0)
			}
		}
	}
	// The parser retains redirects in word text. FD copies do not write files.
	for _, word := range words {
		t := strings.ReplaceAll(word.text, "2>&1", "")
		if strings.Contains(t, ">") && (w.cwdChanged || strings.ContainsAny(wordTexts(words), "$`*?{[")) {
			return agentResult("agent_ambiguous_redirect", CmdCategoryRedirect, 1.0)
		}
	}
	if name == "find" && w.cwdChanged {
		for _, a := range args {
			if a.text == "-delete" {
				return agentResult("agent_cwd_mutation", CmdCategoryDestructive, 1.0)
			}
		}
	}
	if w.defined[name] {
		return agentResult("agent_defined_function", CmdCategoryEscape, 1.0)
	}
	if r := w.strictLine(strings.TrimSpace(name + " " + wordTexts(args))); r != nil {
		return r
	}
	if name == "rm" && !rmTargetsHarmless(args) {
		return agentResult("rm_rf_dot", CmdCategoryDestructive, 1.0)
	}
	if name == "xargs" && !xargsIsPlain(args) {
		return agentResult("pipe_xargs", CmdCategoryPipe, 1.0)
	}
	if name == "find" {
		if r := findVerdict(args); r != nil {
			return r
		}
	}
	for _, s := range innerScripts(name, args) {
		if r := w.script(s); r != nil {
			return r
		}
	}
	for _, inner := range innerCommands(name, args) {
		w.depth++
		r := w.command(inner)
		w.depth--
		if r != nil {
			return r
		}
	}
	return nil
}

// agentDangerousTarget is a path whose recursive removal is never a build
// step: the root, a home folder or anything at its top, a home dot folder or
// Library, the working folder or its parent, a bare glob, or a top-level
// system folder.
func agentDangerousTarget(t string) bool {
	t = strings.TrimSpace(t)
	if t == "" {
		return true
	}
	trimmed := strings.TrimRight(t, "/")
	switch trimmed {
	case "", ".", "..", "*", ".*", "./*", "../*", "/*", "~", "~/*":
		return true
	}
	if strings.HasPrefix(t, "~/") {
		rest := strings.TrimRight(t[2:], "/")
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

var findFilters = map[string]bool{"-name": true, "-iname": true, "-path": true, "-ipath": true, "-regex": true, "-iregex": true, "-newer": true, "-mtime": true, "-mmin": true, "-size": true, "-user": true, "-wholename": true}

// findVerdict denies a delete, or an exec'd rm, shred or unlink, over a start
// path that is never a build folder (or over `.` with nothing narrowing it).
func findVerdict(args []shWord) *CommandInjectionResult {
	var starts []string
	i := 0
	for ; i < len(args); i++ {
		t := args[i].text
		if strings.HasPrefix(t, "-") || t == "(" || t == "!" {
			break
		}
		starts = append(starts, t)
	}
	filtered, deletes := false, false
	for _, a := range args[i:] {
		if findFilters[a.text] {
			filtered = true
		}
		if a.text == "-delete" {
			deletes = true
		}
	}
	for _, inner := range innerCommands("find", args) {
		n, _, _ := splitCommand(inner)
		if n == "rm" || n == "shred" || n == "unlink" {
			deletes = true
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
		if (trimmed == "." || trimmed == "..") && filtered {
			continue
		}
		if !literalPath(s) || agentDangerousTarget(s) {
			return agentResult("find_exec_destructive", CmdCategoryDestructive, 1.0)
		}
	}
	return nil
}
