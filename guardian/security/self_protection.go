// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Self-protection analysis.
//
// The regex patterns named guardclaw_* in CommandInjectionPatterns match the
// guard's full names in one command. Two things a regex cannot do are done
// here instead:
//
//   - Split a command line the way a shell does, respecting single and double
//     quotes, backslash escapes, $( ) and backticks, so `pkill -f 'x|guardclaw'`
//     is one pkill with one target and `pgrep -l guardclaw; ./kill-switch.sh`
//     is two commands.
//   - Read a pkill/pgrep (and killall -r) target as the regex those tools use,
//     and ask whether it selects a guard process.
//
// This is still a static check of one command string. It does not expand
// variables (other than a PID captured from pgrep earlier in the same input),
// aliases, functions, globs against the filesystem or scripts. A daemon that
// must survive a hostile agent needs OS-level protection as well.

// Pattern names reported by MatchSelfProtection. They are the names of the
// corresponding regex patterns, so callers see one ID set.
const (
	selfProtectService  = "guardclaw_service_stop"
	selfProtectLaunchd  = "guardclaw_launchctl_disable"
	selfProtectKill     = "guardclaw_process_kill"
	selfProtectTaskkill = "guardclaw_taskkill"
	selfProtectWinSvc   = "guardclaw_sc_stop"
)

// SelfProtectionPatternNames lists the pattern names MatchSelfProtection can
// return.
func SelfProtectionPatternNames() []string {
	return []string{selfProtectService, selfProtectLaunchd, selfProtectKill, selfProtectTaskkill, selfProtectWinSvc}
}

const (
	// shMaxDepth bounds nested $( ) and backticks. Deeper input fails closed.
	shMaxDepth = 16
	// spRegexBudget bounds how many pkill/pgrep targets are compiled per
	// input. Input with more targets fails closed.
	spRegexBudget = 16
	// spMaxTarget bounds one regex target. Longer targets fail closed.
	spMaxTarget = 256
	// spMinOverlap is how many characters of a guard name a regex target's
	// match must cover to count. See regexSelectsGuard.
	spMinOverlap = 5
)

// guardProcess is a process name or command line a guard runs under, with the
// byte span of the guard name inside it.
type guardProcess struct {
	text       string
	start, end int
}

var guardProcesses = []guardProcess{
	{"guardclaw", 0, 9},
	{"guardclaw-daemon", 0, 9},
	{"com.guardclaw.daemon", 4, 13},
	{"/usr/local/bin/guardclaw", 15, 24},
	{"guardian", 0, 8},
	{"guardiand", 0, 8},
}

// guardUnitNames are service, unit, label and image names (suffix removed)
// that a glob argument is tested against.
var guardUnitNames = []string{
	"guardclaw", "guardclaw-daemon", "com.guardclaw.daemon", "ai.guardclaw.agent",
	"guardian", "guardiand",
}

// MatchSelfProtection reports whether cmd stops, disables, deletes or kills a
// guard service or process, and which self-protection pattern name applies.
func MatchSelfProtection(cmd string) (string, bool) {
	if cmd == "" {
		return "", false
	}
	p := &shParser{s: cmd}
	cmds := p.parseList(0)
	if p.overflow {
		return selfProtectKill, true
	}
	st := &spState{vars: map[string]bool{}, budget: spRegexBudget}
	return st.list(cmds)
}

// ---------------------------------------------------------------------------
// Shell-style splitting

type shWord struct {
	text string    // unquoted, unescaped text; substitutions are omitted
	subs [][]shCmd // command substitutions inside the word
}

type shCmd struct {
	words []shWord
	pipe  bool // stdout is piped into the next command
}

type shParser struct {
	s        string
	i        int
	depth    int
	overflow bool
}

// parseList parses commands until term (')' for $( ), '`' for backticks, 0
// for end of input).
func (p *shParser) parseList(term byte) []shCmd {
	var (
		cmds   []shCmd
		cur    shCmd
		w      strings.Builder
		subs   [][]shCmd
		inWord bool
		parens int
	)
	endWord := func() {
		if inWord {
			cur.words = append(cur.words, shWord{text: w.String(), subs: subs})
			w.Reset()
			subs = nil
			inWord = false
		}
	}
	endCmd := func(pipe bool) {
		endWord()
		if len(cur.words) > 0 {
			cur.pipe = pipe
			cmds = append(cmds, cur)
		}
		cur = shCmd{}
	}
	for p.i < len(p.s) {
		c := p.s[p.i]
		if term != 0 && c == term && (term != ')' || parens == 0) {
			p.i++
			endCmd(false)
			return cmds
		}
		next := byte(0)
		if p.i+1 < len(p.s) {
			next = p.s[p.i+1]
		}
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			endWord()
			p.i++
		case c == '\n' || c == ';':
			endCmd(false)
			p.i++
		case c == '&':
			p.i++
			if next == '&' {
				p.i++
			}
			endCmd(false)
		case c == '|':
			p.i++
			switch next {
			case '|':
				p.i++
				endCmd(false)
			case '&':
				p.i++
				endCmd(true)
			default:
				endCmd(true)
			}
		case c == '(':
			parens++
			endCmd(false)
			p.i++
		case c == ')':
			if parens > 0 {
				parens--
			}
			endCmd(false)
			p.i++
		case c == '#' && !inWord:
			for p.i < len(p.s) && p.s[p.i] != '\n' {
				p.i++
			}
		case c == '\'':
			inWord = true
			p.i++
			if j := strings.IndexByte(p.s[p.i:], '\''); j >= 0 {
				w.WriteString(p.s[p.i : p.i+j])
				p.i += j + 1
			} else {
				w.WriteString(p.s[p.i:])
				p.i = len(p.s)
			}
		case c == '"':
			inWord = true
			p.i++
			p.readDouble(&w, &subs)
		case c == '\\':
			inWord = true
			p.i++
			if p.i < len(p.s) {
				if p.s[p.i] != '\n' {
					w.WriteByte(p.s[p.i])
				}
				p.i++
			}
		case c == '$' && next == '(':
			inWord = true
			p.i += 2
			subs = append(subs, p.sub(')'))
		case c == '`':
			inWord = true
			p.i++
			subs = append(subs, p.sub('`'))
		default:
			inWord = true
			w.WriteByte(c)
			p.i++
		}
	}
	endCmd(false)
	return cmds
}

func (p *shParser) sub(term byte) []shCmd {
	if p.depth >= shMaxDepth {
		p.overflow = true
		p.i = len(p.s) // stop parsing; the caller fails closed
		return nil
	}
	p.depth++
	defer func() { p.depth-- }()
	return p.parseList(term)
}

// readDouble reads a double-quoted string body after the opening quote.
func (p *shParser) readDouble(w *strings.Builder, subs *[][]shCmd) {
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return
		case c == '\\' && p.i+1 < len(p.s) && strings.IndexByte("$`\"\\\n", p.s[p.i+1]) >= 0:
			if p.s[p.i+1] != '\n' {
				w.WriteByte(p.s[p.i+1])
			}
			p.i += 2
		case c == '$' && p.i+1 < len(p.s) && p.s[p.i+1] == '(':
			p.i += 2
			*subs = append(*subs, p.sub(')'))
		case c == '`':
			p.i++
			*subs = append(*subs, p.sub('`'))
		default:
			w.WriteByte(c)
			p.i++
		}
	}
}

// ---------------------------------------------------------------------------
// Command analysis

type spState struct {
	vars   map[string]bool // variables holding a guard PID from pgrep/pidof
	budget int
}

var shIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var shVarRef = regexp.MustCompile(`^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$`)

// list analyzes a command list in order.
func (st *spState) list(cmds []shCmd) (string, bool) {
	for i, c := range cmds {
		for _, w := range c.words {
			for _, sub := range w.subs {
				if n, ok := st.list(sub); ok {
					return n, true
				}
			}
		}
		name, args, assigns := splitCommand(c.words)
		if name == "export" || name == "local" || name == "declare" || name == "readonly" || name == "typeset" {
			assigns = append(assigns, args...)
		}
		for _, a := range assigns {
			eq := strings.IndexByte(a.text, '=')
			if eq <= 0 || !shIdent.MatchString(a.text[:eq]) {
				continue
			}
			for _, sub := range a.subs {
				if st.subSelectsGuard(sub) {
					st.vars[a.text[:eq]] = true
				}
			}
		}
		var prev, next *shCmd
		if i > 0 && cmds[i-1].pipe {
			prev = &cmds[i-1]
		}
		if c.pipe && i+1 < len(cmds) {
			next = &cmds[i+1]
		}
		if n, ok := st.command(name, args, prev, next); ok {
			return n, true
		}
	}
	return "", false
}

// splitCommand returns the command name (base name, case-folded, .exe
// removed), its arguments and any leading VAR=value assignments, skipping
// wrappers such as sudo, env and nohup.
func splitCommand(words []shWord) (string, []shWord, []shWord) {
	var assigns []shWord
	i := 0
	for i < len(words) {
		t := words[i].text
		if eq := strings.IndexByte(t, '='); eq > 0 && shIdent.MatchString(t[:eq]) {
			assigns = append(assigns, words[i])
			i++
			continue
		}
		switch strings.ToLower(t) {
		case "{", "!", "then", "do", "else", "elif", "if", "while", "until", "time",
			"nohup", "exec", "command", "builtin", "noglob":
			i++
			continue
		case "sudo", "doas", "env", "nice", "timeout", "stdbuf", "ionice", "chroot":
			i = skipWrapper(words, i)
			continue
		}
		break
	}
	if i >= len(words) {
		return "", nil, assigns
	}
	name := strings.ToLower(words[i].text)
	if j := strings.LastIndexAny(name, `/\`); j >= 0 {
		name = name[j+1:]
	}
	name = strings.TrimSuffix(name, ".exe")
	return name, words[i+1:], assigns
}

// skipWrapper skips a wrapper command and its options, returning the index
// of the wrapped command.
func skipWrapper(words []shWord, i int) int {
	wrapper := strings.ToLower(words[i].text)
	i++
	withArg := map[string]string{
		"sudo":    "ugpChUTrt",
		"doas":    "uC",
		"env":     "uSC",
		"nice":    "n",
		"timeout": "sk",
		"stdbuf":  "ioe",
		"ionice":  "cnp",
		"chroot":  "",
	}[wrapper]
	for i < len(words) {
		t := words[i].text
		if t == "--" {
			return i + 1
		}
		if wrapper == "env" {
			if eq := strings.IndexByte(t, '='); eq > 0 && shIdent.MatchString(t[:eq]) {
				i++
				continue
			}
		}
		if strings.HasPrefix(t, "-") && len(t) > 1 {
			i++
			if !strings.HasPrefix(t, "--") && len(t) == 2 && strings.IndexByte(withArg, t[1]) >= 0 {
				i++
			}
			continue
		}
		if wrapper == "timeout" || (wrapper == "chroot" && i < len(words)) {
			// timeout DURATION CMD, chroot DIR CMD
			return i + 1
		}
		return i
	}
	return i
}

func (st *spState) command(name string, args []shWord, prev, next *shCmd) (string, bool) {
	switch name {
	case "pkill":
		if st.procSelects(name, args) {
			return selfProtectKill, true
		}
	case "killall":
		if st.procSelects(name, args) {
			return selfProtectKill, true
		}
	case "kill":
		for _, a := range args {
			for _, sub := range a.subs {
				if st.subSelectsGuard(sub) {
					return selfProtectKill, true
				}
			}
			if m := shVarRef.FindStringSubmatch(a.text); m != nil && st.vars[m[1]] {
				return selfProtectKill, true
			}
		}
	case "pgrep", "pidof":
		if next != nil {
			nn, nargs, _ := splitCommand(next.words)
			if nn == "xargs" && hasWord(nargs, "kill") && st.procSelects(name, args) {
				return selfProtectKill, true
			}
		}
	case "systemctl":
		if verb, rest := firstOperand(args, "sHMptno"); verb != "" {
			switch strings.ToLower(verb) {
			case "stop", "kill", "disable", "mask":
				if anyOperandMatches(rest) {
					return selfProtectService, true
				}
			}
		}
	case "service":
		if hasWord(args, "stop") && anyOperandMatches(args) {
			return selfProtectService, true
		}
	case "launchctl":
		if verb, rest := firstOperand(args, ""); verb != "" {
			switch strings.ToLower(verb) {
			case "unload", "disable", "bootout", "remove", "kill", "stop":
				if anyOperandMatches(rest) {
					return selfProtectLaunchd, true
				}
			}
		}
	case "rm", "mv", "unlink", "shred", "srm", "trash":
		for _, a := range args {
			if n, ok := serviceFileMatch(a.text); ok {
				return n, true
			}
		}
	case "taskkill":
		for i := 0; i+1 < len(args); i++ {
			switch strings.ToLower(args[i].text) {
			case "/im":
				if guardNameMatch(args[i+1].text) {
					return selfProtectTaskkill, true
				}
			case "/fi":
				f := strings.Fields(strings.ToLower(args[i+1].text))
				if len(f) == 3 && f[0] == "imagename" && f[1] == "eq" && guardNameMatch(f[2]) {
					return selfProtectTaskkill, true
				}
			}
		}
	case "stop-process":
		if anyOperandMatches(args) || pipedFromMatching(prev, "get-process") {
			return selfProtectTaskkill, true
		}
	case "sc":
		for i, a := range args {
			switch strings.ToLower(a.text) {
			case "stop", "delete", "config":
				if anyOperandMatches(args[i+1:]) {
					return selfProtectWinSvc, true
				}
			}
		}
	case "stop-service", "suspend-service", "remove-service":
		if anyOperandMatches(args) || pipedFromMatching(prev, "get-service") {
			return selfProtectWinSvc, true
		}
	case "set-service":
		if anyOperandMatches(args) && startupDisabled(args) {
			return selfProtectWinSvc, true
		}
	}
	return "", false
}

// subSelectsGuard reports whether a command substitution runs pgrep or pidof
// for a guard process (or reads a guard PID file).
func (st *spState) subSelectsGuard(cmds []shCmd) bool {
	for _, c := range cmds {
		name, args, _ := splitCommand(c.words)
		switch name {
		case "pgrep", "pidof":
			if st.procSelects(name, args) {
				return true
			}
		case "cat", "head", "tail":
			for _, a := range args {
				l := foldCase(a.text)
				if strings.HasSuffix(l, ".pid") && (strings.Contains(l, "guardclaw") || strings.Contains(l, "guardian")) {
					return true
				}
			}
		}
	}
	return false
}

// procSelects reports whether a pkill, pgrep, killall or pidof invocation
// selects a guard process.
func (st *spState) procSelects(tool string, args []shWord) bool {
	var argLetters string
	regexMode := tool == "pkill" || tool == "pgrep"
	switch tool {
	case "pkill", "pgrep":
		argLetters = "dgGPstuUFOrq"
	case "killall":
		argLetters = "sunoyZt"
	case "pidof":
		argLetters = "o"
	}
	var exact, inverse bool
	var targets []string
	for i := 0; i < len(args); i++ {
		t := args[i].text
		if t == "--" {
			for _, a := range args[i+1:] {
				targets = append(targets, a.text)
			}
			break
		}
		if strings.HasPrefix(t, "--") {
			key, _, hasVal := strings.Cut(t[2:], "=")
			switch key {
			case "exact":
				exact = true
			case "inverse":
				inverse = true
			case "regexp":
				regexMode = true
			case "signal", "group", "pgroup", "session", "terminal", "euid", "uid", "pidfile",
				"ns", "nslist", "older", "younger", "runstates", "delimiter", "parent", "user", "context":
				if !hasVal {
					i++
				}
			}
			continue
		}
		if strings.HasPrefix(t, "-") && len(t) > 1 {
			flags := t[1:]
			if len(flags) == 1 && strings.IndexByte(argLetters, flags[0]) >= 0 {
				// -F pidfile: a guard PID file selects the guard.
				if flags[0] == 'F' && i+1 < len(args) {
					l := foldCase(args[i+1].text)
					if strings.Contains(l, "guardclaw") || strings.Contains(l, "guardian") {
						return true
					}
				}
				i++
				continue
			}
			if tool == "pkill" || tool == "killall" {
				if isSignalFlag(flags) {
					continue
				}
			}
			for k := 0; k < len(flags); k++ {
				f := flags[k]
				switch {
				case f == 'x' && tool != "killall":
					exact = true
				case f == 'v' && tool != "killall":
					inverse = true
				case (f == 'r' || f == 'm') && tool == "killall":
					regexMode = true
				case f == 'c' && tool == "killall":
					// macOS killall -c NAME restricts by command name.
					if k == len(flags)-1 && i+1 < len(args) {
						i++
						targets = append(targets, args[i].text)
					}
					k = len(flags)
				case strings.IndexByte(argLetters, f) >= 0:
					if k == len(flags)-1 {
						i++
					}
					k = len(flags)
				}
			}
			continue
		}
		targets = append(targets, t)
	}
	for _, t := range targets {
		var selected bool
		if regexMode {
			selected = st.regexSelectsGuard(t, exact)
		} else {
			selected = exactNameMatch(t)
		}
		if selected != inverse {
			return true
		}
	}
	return false
}

// isSignalFlag reports whether a dash-flag body is a signal (-9, -KILL,
// -SIGTERM) rather than option letters.
func isSignalFlag(flags string) bool {
	if flags == "" {
		return false
	}
	allDigits, allUpper := true, true
	for i := 0; i < len(flags); i++ {
		c := flags[i]
		if c < '0' || c > '9' {
			allDigits = false
		}
		if !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '+' && c != '-' {
			allUpper = false
		}
	}
	return allDigits || allUpper
}

// quantifierRun collapses stacked quantifiers (a++, a*+) that POSIX regex
// tools accept and Go's RE2 syntax rejects.
var quantifierRun = regexp.MustCompile(`([*+?])[*+?]+`)

// regexSelectsGuard reads target as the extended regex pkill and pgrep use
// (case-insensitively, to cover process names in any case) and reports whether
// it selects a guard process.
//
// Without -x those tools match the regex anywhere in the name or command
// line, so a regex like 'law.*' technically also matches "guardclaw". To keep
// ordinary targets such as 'law.*', 'node.*claude' or 'guardrail' usable, a
// target counts only when its match covers at least spMinOverlap characters
// of the guard name itself: 'guardcl.w', 'x|guardclaw', 'uardclaw' and '.*'
// count; 'law.*' (three characters of the name) does not. With -x the whole
// name must match.
//
// Targets that do not compile even after collapsing stacked quantifiers, are
// longer than spMaxTarget, or exceed the per-input budget fail closed.
func (st *spState) regexSelectsGuard(target string, exact bool) bool {
	st.budget--
	if st.budget < 0 || len(target) > spMaxTarget {
		return true
	}
	suffix := `)`
	if exact {
		suffix = `)$`
	}
	re, err := regexp.Compile(`(?i)^(?:` + target + suffix)
	if err != nil {
		re, err = regexp.Compile(`(?i)^(?:` + quantifierRun.ReplaceAllString(target, "$1") + suffix)
		if err != nil {
			return true
		}
	}
	if exact {
		for _, gp := range guardProcesses {
			if re.MatchString(gp.text) {
				return true
			}
		}
		return false
	}
	// For each start position, the longest match from there has the largest
	// overlap with the guard name of any match from there, so one
	// leftmost-longest search per start position is enough.
	re.Longest()
	for _, gp := range guardProcesses {
		for i := 0; i <= gp.end-spMinOverlap; i++ {
			loc := re.FindStringIndex(gp.text[i:])
			if loc == nil {
				continue
			}
			lo, hi := i, i+loc[1]
			if lo < gp.start {
				lo = gp.start
			}
			if hi > gp.end {
				hi = gp.end
			}
			if hi-lo >= spMinOverlap {
				return true
			}
		}
	}
	return false
}

// exactNameMatch is killall/pidof name matching: the whole process name.
func exactNameMatch(t string) bool {
	l := foldCase(t)
	if j := strings.LastIndexByte(l, '/'); j >= 0 {
		l = l[j+1:]
	}
	for _, gp := range guardProcesses {
		if l == gp.text {
			return true
		}
	}
	return false
}

// guardNameMatch reports whether a service, unit, label or image argument
// names a guard: it contains "guardclaw" or "guardian", or it is a glob that
// matches one of guardUnitNames.
func guardNameMatch(arg string) bool {
	a := foldCase(strings.TrimSpace(arg))
	if j := strings.LastIndexAny(a, `/\`); j >= 0 {
		a = a[j+1:]
	}
	for _, suffix := range []string{".service", ".exe", ".plist"} {
		a = strings.TrimSuffix(a, suffix)
	}
	if a == "" {
		return false
	}
	if strings.ContainsAny(a, "*?[") {
		for _, n := range guardUnitNames {
			if ok, _ := filepath.Match(a, n); ok {
				return true
			}
		}
		return false
	}
	return strings.Contains(a, "guardclaw") || strings.Contains(a, "guardian")
}

// serviceFileMatch reports whether a path argument to rm or mv names a
// guard's launchd plist or systemd unit.
func serviceFileMatch(arg string) (string, bool) {
	l := foldCase(arg)
	base := l
	if j := strings.LastIndexByte(l, '/'); j >= 0 {
		base = l[j+1:]
	}
	switch {
	case strings.HasSuffix(base, ".plist") && (strings.Contains(l, "launchdaemons/") || strings.Contains(l, "launchagents/")):
		if guardNameMatch(base) {
			return selfProtectLaunchd, true
		}
	case strings.HasSuffix(base, ".service"):
		if guardNameMatch(base) {
			return selfProtectService, true
		}
	}
	return "", false
}

// firstOperand returns the first non-option argument and the arguments after
// it. Letters in argLetters are short options that take a separate value.
func firstOperand(args []shWord, argLetters string) (string, []shWord) {
	for i := 0; i < len(args); i++ {
		t := args[i].text
		if strings.HasPrefix(t, "-") && len(t) > 1 {
			if len(t) == 2 && strings.IndexByte(argLetters, t[1]) >= 0 {
				i++
			}
			continue
		}
		return t, args[i+1:]
	}
	return "", nil
}

func anyOperandMatches(args []shWord) bool {
	for _, a := range args {
		if strings.HasPrefix(a.text, "-") {
			continue
		}
		if guardNameMatch(a.text) {
			return true
		}
	}
	return false
}

func pipedFromMatching(prev *shCmd, tool string) bool {
	if prev == nil {
		return false
	}
	name, args, _ := splitCommand(prev.words)
	return name == tool && anyOperandMatches(args)
}

func startupDisabled(args []shWord) bool {
	for i, a := range args {
		l := strings.ToLower(a.text)
		if l == "-startuptype:disabled" {
			return true
		}
		if l == "-startuptype" && i+1 < len(args) && strings.EqualFold(args[i+1].text, "disabled") {
			return true
		}
	}
	return false
}

func hasWord(args []shWord, w string) bool {
	for _, a := range args {
		if strings.EqualFold(a.text, w) {
			return true
		}
		if j := strings.LastIndexByte(a.text, '/'); j >= 0 && strings.EqualFold(a.text[j+1:], w) {
			return true
		}
	}
	return false
}
