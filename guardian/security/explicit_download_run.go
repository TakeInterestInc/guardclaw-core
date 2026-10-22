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
	if agentChangesDirectory(input) {
		return false
	}
	p := &shParser{s: input}
	state := &explicitDownloadRun{files: make(map[string]bool)}
	state.list(p.parseList(0), 0)
	return state.bad
}

type explicitDownloadRun struct {
	files map[string]bool
	bad   bool
}

func literalDownloadPath(value string) (string, bool) {
	if value == "" || value == "-" || strings.ContainsAny(value, "$\x60*?{[~\\\x00<>") {
		return "", false
	}
	return path.Clean(value), true
}

func (s *explicitDownloadRun) matches(value string) bool {
	file, ok := literalDownloadPath(value)
	return ok && s.files[file]
}

func (s *explicitDownloadRun) list(commands []shCmd, depth int) {
	if depth > shMaxDepth {
		return // agent mode independently refuses excessive nesting
	}
	for _, command := range commands {
		for _, word := range command.words {
			for _, sub := range word.subs {
				s.list(sub, depth+1)
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
	i, _ := commandIndex(words)
	if i >= len(words) {
		return
	}
	name, args, _ := splitCommand(words)
	if strings.ContainsAny(words[i].text, "/\\") && s.matches(words[i].text) {
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
		if len(fileArgs) > 0 && s.matches(fileArgs[0].text) {
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
		s.list(p.parseList(0), depth+1)
	}
	for _, inner := range innerCommands(name, args) {
		s.words(inner, depth+1)
	}
}

// Match only file-taking shell forms whose option semantics are known here.
// Inline programs are opened by innerScripts; -s reads stdin. Other startup
// files and shell-specific option forms remain outside this narrow boundary.
func literalShellFile(name string, args []shWord) (string, bool) {
	if shellSyntaxOnly(name, args) {
		return "", false
	}
	for i, arg := range args {
		t := arg.text
		if t == "--" {
			if i+1 < len(args) {
				return args[i+1].text, true
			}
			return "", false
		}
		if t == "" || (t[0] != '-' && t[0] != '+') {
			return t, true
		}
		if (name != "bash" && strings.ContainsRune(t[1:], 'n')) || t == "-" || t == "+" || strings.HasPrefix(t, "--") || strings.Trim(t[1:], "efnuvxilpr") != "" {
			return "", false
		}
	}
	return "", false
}

var literalCurlFlags = strings.Fields("fail fail-with-body silent show-error location location-trusted insecure compressed globoff head ipv4 ipv6 http1.0 http1.1 http2 no-progress-meter")
var literalCurlValues = strings.Fields("url header data data-raw data-binary data-urlencode request user user-agent connect-timeout max-time retry retry-delay retry-max-time proxy proxy-user referer cookie form upload-file range resolve connect-to cacert capath cert key")
var literalWgetFlags = strings.Fields("quiet verbose no-verbose continue timestamping no-check-certificate server-response")
var literalWgetValues = strings.Fields("output-file append-output directory-prefix header user-agent timeout tries proxy-user proxy-password post-data post-file user password accept reject")

// Read a bounded, documented option grammar, rather than treating an option's
// value (for example curl -H '--output') as another option. Unsupported modes
// return no proven outputs; their broader provenance remains tracked in #14.
// Redirections stripped by the shared helper do not become option operands;
// any remaining operator-bearing word is outside this literal grammar.
func explicitFetchOutputs(name string, args []shWord) []string {
	var files []string
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
		if strings.ContainsAny(t, "<>") {
			return nil // unresolved operator-bearing words are outside this grammar
		}
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
				if strings.ContainsAny(value, "<>") {
					return nil
				}
				files = append(files, value)
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
					files = append(files, value)
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
