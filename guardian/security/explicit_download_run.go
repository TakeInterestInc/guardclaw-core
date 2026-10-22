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
	state := &explicitDownloadRun{files: make(map[string]bool)}
	state.list(p.parseList(0), 0)
	return state.bad
}

type explicitDownloadRun struct {
	files      map[string]bool
	parent     *explicitDownloadRun // inherited identities without copying the map
	bad        bool
	cwdChanged bool
}

func (s *explicitDownloadRun) changeDirectory() {
	s.cwdChanged = true
	for file := range s.files {
		if !path.IsAbs(file) {
			delete(s.files, file)
		}
	}
}

func (s *explicitDownloadRun) childState(inherit bool) *explicitDownloadRun {
	child := &explicitDownloadRun{files: make(map[string]bool)}
	if inherit {
		child.parent = s
	}
	return child
}

func (s *explicitDownloadRun) absorbChild(child *explicitDownloadRun, propagate bool) {
	s.bad = s.bad || child.bad
	if !propagate {
		return
	}
	for file := range child.files {
		if !child.cwdChanged || path.IsAbs(file) {
			s.files[file] = true
		}
	}
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
	for scope := s; scope != nil; scope = scope.parent {
		if scope.files[file] {
			return true
		}
		if scope.cwdChanged && !path.IsAbs(file) {
			return false
		}
	}
	return false
}

func (s *explicitDownloadRun) list(commands []shCmd, depth int) {
	if depth > shMaxDepth {
		return // agent mode independently refuses excessive nesting
	}
	for _, command := range commands {
		for _, word := range command.words {
			for _, sub := range word.subs {
				child := s.childState(true)
				child.list(sub, depth+1)
				s.absorbChild(child, true)
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
		// changed root isolates both inputs and outputs. Relative identities
		// are invalidated by the child's cwd effect.
		child := s.childState(!wrapperRoot)
		child.changeDirectory()
		child.words(words[i:], depth+1)
		s.absorbChild(child, !wrapperRoot)
		return
	}
	name, args, _ := splitCommand(words)
	if name == "cd" || name == "pushd" || name == "popd" {
		s.changeDirectory()
		return
	}
	if strings.Contains(words[i].text, "/") && s.matches(words[i]) {
		s.bad = true
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
		if len(fileArgs) > 0 && s.matches(fileArgs[0]) {
			s.bad = true
		}
	} else if name == "sh" || name == "bash" || name == "dash" || name == "ksh" || name == "zsh" || name == "ash" {
		if file, ok := literalShellFile(name, fileArgs); ok && s.matches(file) {
			s.bad = true
		}
	}
	if name == "curl" || name == "wget" {
		for _, file := range explicitFetchOutputs(name, fileArgs) {
			if clean, ok := literalDownloadPath(file); ok {
				s.files[clean] = true
			}
		}
	}
	for _, inner := range innerScripts(name, args) {
		p := &shParser{s: inner}
		commands := p.parseList(0)
		if name == "eval" {
			s.list(commands, depth+1)
		} else {
			child := s.childState(true)
			child.list(commands, depth+1)
			s.absorbChild(child, true)
		}
	}
	// find's expression/value grammar and -execdir working directory need a
	// separate model. Do not infer provenance inside its command templates.
	if name != "find" {
		for _, inner := range innerCommands(name, args) {
			child := s.childState(true)
			child.words(inner, depth+1)
			s.absorbChild(child, true)
		}
	}
}

// Match only file-taking shell forms whose option semantics are known here.
// Inline programs are opened by innerScripts; -s reads stdin. Other startup
// files and shell-specific option forms remain outside this narrow boundary.
func literalShellFile(name string, args []shWord) (shWord, bool) {
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
	var files []shWord
	flagOptions, valueOptions := literalCurlFlags, literalCurlValues
	valueLetters, plainLetters, outputLetter := "HduAXxUebFTr", "fsSLqvIk", byte('o')
	outputName := "output"
	if name == "wget" {
		flagOptions, valueOptions = literalWgetFlags, literalWgetValues
		valueLetters, plainLetters, outputLetter = "oPU", "qvcNS", 'O'
		outputName = "output-document"
	}
	for i := 0; i < len(args); i++ {
		t := args[i].text
		if t == "--" {
			break
		}
		if strings.HasPrefix(t, "--") {
			key, value, attached := strings.Cut(t[2:], "=")
			switch {
			case key == outputName:
				if !attached {
					i++
					if i >= len(args) {
						return nil
					}
					value = args[i].text
				}
				word := args[i]
				word.text = value
				files = append(files, word)
			case rsyncContains(valueOptions, key):
				if !attached {
					i++
					if i >= len(args) {
						return nil
					}
				}
			case rsyncContains(flagOptions, key) && !attached:
			default:
				return nil
			}
		} else if strings.HasPrefix(t, "-") && t != "-" {
			for j := 1; j < len(t); j++ {
				switch {
				case t[j] == outputLetter:
					value := t[j+1:]
					if value == "" {
						i++
						if i >= len(args) {
							return nil
						}
						value = args[i].text
					}
					word := args[i]
					word.text = value
					files = append(files, word)
					j = len(t)
				case strings.ContainsRune(valueLetters, rune(t[j])):
					if j == len(t)-1 {
						i++
						if i >= len(args) {
							return nil
						}
					}
					j = len(t)
				case strings.ContainsRune(plainLetters, rune(t[j])):
				default:
					return nil
				}
			}
		}
	}
	return files
}

func explicitDownloadRunResult() *CommandInjectionResult {
	return &CommandInjectionResult{Detected: true, Score: 1, Confidence: 1,
		Category: CmdCategoryBackdoor, PatternName: "download_then_run",
		Reason: "Command injection detected: execution of a literal file downloaded in the same input"}
}
