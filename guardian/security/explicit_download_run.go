// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"path"
	"strings"
)

// This is deliberately a literal, same-input boundary. It does not infer
// filesystem aliases, changed directories, config-selected output names,
// arbitrary interpreter loaders, or effects from an earlier invocation.
func matchExplicitDownloadRun(input string) bool {
	p := &shParser{s: input}
	state := &explicitDownloadRun{context: &downloadWrites{files: make(map[downloadIdentity]bool)}}
	state.list(p.parseList(0), 0)
	return state.context.bad
}

// Writes persist independently of process location. Opaque location tokens do
// not infer equivalence after cd or root changes; see the documented #14 limits.
type downloadIdentity struct {
	root, cwd uint64
	file      string
}
type downloadWrites struct {
	files map[downloadIdentity]bool
	next  uint64
	bad   bool
}
type explicitDownloadRun struct {
	context   *downloadWrites
	root, cwd uint64
}

func (s *explicitDownloadRun) token() uint64                    { s.context.next++; return s.context.next }
func (s *explicitDownloadRun) changeDirectory()                 { s.cwd = s.token() }
func (s *explicitDownloadRun) childState() *explicitDownloadRun { child := *s; return &child }
func (s *explicitDownloadRun) identity(file string) downloadIdentity {
	key := downloadIdentity{root: s.root, cwd: s.cwd, file: file}
	if path.IsAbs(file) {
		key.cwd = 0
	}
	return key
}

// Cooked metacharacters can be literal when quoted or escaped. Consult the
// original spelling instead of treating every cooked '$' or '*' as expansion.
func literalDownloadPath(word shWord) (string, bool) {
	if word.text == "" || word.text == "-" || !downloadWordIsLiteral(word) {
		return "", false
	}
	return path.Clean(word.text), true
}

func downloadWordIsLiteral(word shWord) bool {
	if len(word.subs) > 0 || strings.ContainsRune(word.text, 0) {
		return false
	}
	raw := word.rawSource
	if raw == "" {
		// A prefix retained by redirection stripping has no quote metadata.
		return !strings.ContainsAny(word.text, "$\x60*?{[~\\<>")
	}
	var quote byte
	ansi := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if quote == '\'' {
			if ansi && c == '\\' {
				i++
			} else if c == '\'' {
				quote, ansi = 0, false
			}
			continue
		}
		if c == '\\' {
			i++
			continue
		}
		if c == '"' {
			if quote == '"' {
				quote = 0
			} else {
				quote = '"'
			}
			continue
		}
		if quote == 0 && c == '\'' {
			quote = '\''
			continue
		}
		if quote == 0 && c == '$' && i+1 < len(raw) && raw[i+1] == '\'' {
			quote, ansi = '\'', true
			i++
			continue
		}
		if c == '$' && i+1 < len(raw) {
			next := raw[i+1]
			if next >= 128 || (next >= 'a' && next <= 'z') || (next >= 'A' && next <= 'Z') ||
				(next >= '0' && next <= '9') || next == '_' || strings.ContainsRune("{([?$#-!@*", rune(next)) ||
				(quote == 0 && next == '"') {
				return false
			}
		}
		if c == '\x60' || (quote == 0 && strings.ContainsRune("*?{[<>", rune(c))) ||
			(quote == 0 && c == '~' && (i == 0 || raw[i-1] == '=' || raw[i-1] == ':')) {
			return false
		}
	}
	return quote == 0
}

func (s *explicitDownloadRun) matches(word shWord) bool {
	file, ok := literalDownloadPath(word)
	if !ok {
		return false
	}
	return s.context.files[s.identity(file)]
}

func (s *explicitDownloadRun) list(commands []shCmd, depth int) {
	if depth > shMaxDepth {
		return // agent mode independently refuses excessive nesting
	}
	for _, command := range commands {
		for _, word := range command.words {
			for _, sub := range word.subs {
				child := s.childState()
				child.list(sub, depth+1)
			}
		}
		s.words(command.words, depth)
	}
}

func (s *explicitDownloadRun) words(words []shWord, depth int) {
	if depth > shMaxDepth {
		return
	}
	words = rsyncWithoutRedirects(words)
	wrapperCwd, wrapperRoot := false, false
	i, _ := commandIndexObserved(words, func(name string, options []shWord) {
		cwd, root := explicitWrapperDirectoryEffect(name, options)
		wrapperCwd = wrapperCwd || cwd
		wrapperRoot = wrapperRoot || root
	})
	if i >= len(words) {
		return
	}
	if wrapperCwd {
		// A cwd-only child shares absolute identities in both directions. A
		// changed root allocates a separate namespace; prior writes remain
		// in the persistent ledger for their original location.
		child := s.childState()
		if wrapperRoot {
			child.root = child.token()
		}
		child.changeDirectory()
		child.words(words[i:], depth+1)
		return
	}
	name, args, _ := splitCommand(words)
	if name == "cd" || name == "pushd" || name == "popd" {
		s.changeDirectory()
		return
	}
	if strings.Contains(words[i].text, "/") && s.matches(words[i]) {
		s.context.bad = true
	}
	if strings.ContainsAny(words[i].text, "/\\") {
		switch name {
		case "sudo", "doas", "env", "nice", "timeout", "stdbuf", "ionice", "chroot", "command", "exec", "time", "nohup":
			// Reuse the existing wrapper option grammar for a wrapper whose
			// executable was spelled by path, preserving the original words.
			inner := append([]shWord(nil), words...)
			inner[i].text = name
			s.words(inner, depth+1)
			return
		}
	}
	fileArgs := rsyncWithoutRedirects(args)
	if name == "." || name == "source" {
		terminated := len(fileArgs) > 0 && fileArgs[0].text == "--"
		if terminated {
			fileArgs = fileArgs[1:]
		}
		if len(fileArgs) > 0 && (terminated || !strings.HasPrefix(fileArgs[0].text, "-")) && s.matches(fileArgs[0]) {
			s.context.bad = true
		}
	} else if name == "sh" || name == "bash" || name == "dash" || name == "ksh" || name == "zsh" || name == "ash" {
		if file, ok := literalShellFile(name, fileArgs); ok && s.matches(file) {
			s.context.bad = true
		}
	}
	if name == "curl" || name == "wget" {
		for _, file := range explicitFetchOutputs(name, fileArgs) {
			if clean, ok := literalDownloadPath(file); ok {
				s.context.files[s.identity(clean)] = true
			}
		}
	}
	for _, inner := range innerScripts(name, args) {
		p := &shParser{s: inner}
		commands := p.parseList(0)
		if name == "eval" {
			s.list(commands, depth+1)
		} else {
			child := s.childState()
			child.list(commands, depth+1)
		}
	}
	// find's expression/value grammar and -execdir working directory need a
	// separate model. Do not infer provenance inside its command templates.
	if name != "find" {
		for _, inner := range innerCommands(name, args) {
			child := s.childState()
			child.words(inner, depth+1)
		}
	}
}

// Match only file-taking shell forms whose option semantics are known here.
// Inline programs are opened by innerScripts; -s reads stdin. Other startup
// files and shell-specific option forms remain outside this narrow boundary.
func literalShellFile(name string, args []shWord) (shWord, bool) {
	if name == "bash" {
		invocation := readBashInvocation(args)
		return invocation.selected, invocation.known && invocation.mode == "file" && !invocation.noexec
	}
	if shellSyntaxOnly(name, args) {
		return shWord{}, false
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		t := arg.text
		// These Bash startup options consume a separate operand. The operand
		// is neither a script filename nor another startup option.
		if name == "bash" && (t == "-o" || t == "+o" || t == "-O" || t == "+O" || t == "--rcfile" || t == "--init-file") {
			i++
			if i >= len(args) {
				return shWord{}, false
			}
			continue
		}
		if t == "--" {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return shWord{}, false
		}
		if t == "" || (t[0] != '-' && t[0] != '+') {
			return arg, true
		}
		if t == "-" || t == "+" || strings.HasPrefix(t, "--") || strings.Trim(t[1:], "efnuvxilpr") != "" {
			return shWord{}, false
		}
	}
	return shWord{}, false
}

// Inspect wrapper options in their parsed command position. Values consumed
// by -u/--unset or sudo's user/group flags cannot become directory options.
// This boundary deliberately does not infer env -S or unknown wrapper syntax.
func explicitWrapperDirectoryEffect(name string, args []shWord) (cwd, root bool) {
	if name == "chroot" {
		return true, true
	}
	if name != "env" && name != "sudo" {
		return false, false
	}
	for i := 0; i < len(args); i++ {
		t := args[i].text
		if t == "--" {
			break
		}
		if len(t) < 2 || t[0] != '-' {
			continue
		}
		operand, change, rootChange := wrapperOption(name, t)
		cwd, root = cwd || change, root || rootChange
		if operand {
			i++
		}
	}
	return
}

var literalCurlFlags = strings.Fields("fail fail-with-body silent show-error location location-trusted insecure compressed globoff head ipv4 ipv6 http1.0 http1.1 http2 no-progress-meter")
var literalCurlValues = strings.Fields("url header data data-raw data-binary data-urlencode request user user-agent connect-timeout max-time retry retry-delay retry-max-time proxy proxy-user referer cookie form upload-file range resolve connect-to cacert capath cert key")
var literalWgetFlags = strings.Fields("quiet verbose no-verbose continue timestamping no-check-certificate server-response")
var literalWgetValues = strings.Fields("output-file append-output directory-prefix header user-agent timeout tries proxy-user proxy-password post-data post-file user password accept reject")

// Read a bounded, documented option grammar, rather than treating an option's
// value (for example curl -H '--output') as another option. Unsupported modes
// return no proven outputs; their broader provenance remains tracked in #14.
// Redirections stripped by the shared helper do not become option operands;
// unquoted residual redirection words are outside this literal grammar.
func explicitFetchOutputs(name string, args []shWord) []shWord {
	var outputs []shWord
	urls := 0
	flagOptions, valueOptions := literalCurlFlags, literalCurlValues
	valueLetters, plainLetters, outputLetter := "HduAXxUebFTr", "fsSLqvIk", byte('o')
	outputName := "output"
	if name == "wget" {
		flagOptions, valueOptions = literalWgetFlags, literalWgetValues
		valueLetters, plainLetters, outputLetter = "oPU", "qvcNS", 'O'
		outputName = "output-document"
	}
	addURL := func(word shWord) bool {
		if word.text == "" || !downloadWordIsLiteral(word) {
			return false
		}
		// Shell quotes do not disable curl's own URL glob interpreter.
		if name == "curl" && strings.ContainsAny(word.text, "{}[]") {
			return false
		}
		urls++
		return true
	}
	positional := false
	for i := 0; i < len(args); i++ {
		word, t := args[i], args[i].text
		if !downloadWordIsLiteral(word) {
			return nil
		}
		if !positional && t == "--" {
			positional = true
			continue
		}
		if positional || !strings.HasPrefix(t, "-") || t == "-" {
			if !addURL(word) {
				return nil
			}
			continue
		}
		if strings.HasPrefix(t, "--") {
			key, value, attached := strings.Cut(t[2:], "=")
			if key == outputName || (key == "url" && name == "curl") || rsyncContains(valueOptions, key) {
				if !attached {
					i++
					if i >= len(args) {
						return nil
					}
					word = args[i]
					value = word.text
				}
				if !downloadWordIsLiteral(word) {
					return nil
				}
				word.text = value
				if key == outputName {
					outputs = append(outputs, word)
				}
				if key == "url" && name == "curl" && !addURL(word) {
					return nil
				}
			} else if !rsyncContains(flagOptions, key) || attached {
				return nil
			}
			continue
		}
		for j := 1; j < len(t); j++ {
			if t[j] == outputLetter || strings.ContainsRune(valueLetters, rune(t[j])) {
				output := t[j] == outputLetter
				value := t[j+1:]
				if value == "" {
					i++
					if i >= len(args) {
						return nil
					}
					word = args[i]
					value = word.text
				}
				if !downloadWordIsLiteral(word) {
					return nil
				}
				word.text = value
				if output {
					outputs = append(outputs, word)
				}
				break
			}
			if !strings.ContainsRune(plainLetters, rune(t[j])) {
				return nil
			}
		}
	}
	if urls != 1 || len(outputs) == 0 {
		return nil
	}
	if name == "curl" && len(outputs) != 1 {
		return nil
	}
	// Wget's -O is a single effective output; repeated selection is last-wins.
	output := outputs[len(outputs)-1]
	if _, ok := literalDownloadPath(output); !ok {
		return nil
	}
	return []shWord{output}
}

func explicitDownloadRunResult() *CommandInjectionResult {
	return &CommandInjectionResult{Detected: true, Score: 1, Confidence: 1,
		Category: CmdCategoryBackdoor, PatternName: "download_then_run",
		Reason: "Command injection detected: execution of a literal file downloaded in the same input"}
}
