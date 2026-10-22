// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0
package security

import "strings"

// Invocation evidence is structural, not a runtime binary or filesystem proof.
// Unknown must survive both descendant traversal and persistent candidate writes.
type invocationCertainty uint8

const (
	invocationUncertain invocationCertainty = iota
	invocationEstablished
)

func weakerInvocation(a, b invocationCertainty) invocationCertainty {
	if a < b {
		return a
	}
	return b
}

type invocationOrigin struct{ profile, reason string }

type invocationRole uint8

const (
	invocationUnowned invocationRole = iota
	invocationOption
	invocationOptionValue
	invocationSource
	invocationData
)

type shellInvocation struct {
	profile         string
	mode            string // file, inline, stdin, unknown
	selected        int
	inlineCandidate int // original source candidate after a proved boundary, still Unknown
	roles           []invocationRole
	noexec          bool // certified suppression only, never true for Unknown
	execution       invocationCertainty
	reason          string // stable internal code, never original source text
}

// wholeSource retains the original word and an explicit cooked span. Legacy
// --command= candidates may use a suffix span; unsupported profile operands
// never manufacture a new shWord with its provenance removed.
type invocationProgram struct {
	original          []shWord
	index, start, end int
	assembled         string // existing eval/watch semantics, with original words retained
	certainty         invocationCertainty
	origin            invocationOrigin
}

func (p invocationProgram) script() string {
	if p.index < 0 {
		return p.assembled
	}
	return p.original[p.index].text[p.start:p.end]
}
func programWord(args []shWord, index, start int, certainty invocationCertainty) invocationProgram {
	return invocationProgram{original: args, index: index, start: start, end: len(args[index].text), certainty: certainty}
}

func invocationShell(name string) bool {
	switch name {
	case "bash", "sh", "dash", "zsh", "ksh", "ash":
		return true
	}
	return false
}

// readShellInvocation accounts for original argv ownership in a single walk.
// Profiles admit bounded documented/native-backed transitions. The first
// unsupported transition owns no exclusions: its whole original word and the
// remaining suffix are Unknown. A later familiar flag cannot resynchronize it.
func readShellInvocation(name string, args []shWord) shellInvocation {
	result := shellInvocation{profile: name, mode: "stdin", selected: -1, inlineCandidate: -1, roles: make([]invocationRole, len(args)), execution: invocationEstablished}
	unknown := func(at int, reason string) shellInvocation {
		for i := at; i < len(result.roles); i++ {
			result.roles[i] = invocationUnowned
		}
		result.mode, result.selected, result.reason, result.noexec, result.execution = "unknown", -1, reason, false, invocationUncertain
		return result
	}
	inline, stdin, noexec, shortSeen, stop := false, false, false, false, false
	finish := func(index int) shellInvocation {
		if stdin && !inline {
			// A proved stdin boundary makes all remaining words positional data,
			// even when expansion can change their count or spelling. Parent
			// substitutions are still traversed independently by the callers.
			result.roles[index] = invocationData
		} else {
			if !downloadWordIsLiteral(args[index]) {
				if inline {
					result.inlineCandidate = index
				}
				return unknown(index, "dynamic_source_word")
			}
			if inline {
				result.mode = "inline"
			} else {
				result.mode = "file"
			}
			result.selected = index
			result.roles[index] = invocationSource
		}
		for j := index + 1; j < len(args); j++ {
			result.roles[j] = invocationData
		}
		result.noexec = noexec && name == "bash"
		if noexec && name != "bash" {
			result.execution = invocationUncertain
		}
		return result
	}
	for i := 0; i < len(args); i++ {
		word, t := args[i], args[i].text
		if stop {
			return finish(i)
		}
		if !downloadWordIsLiteral(word) {
			return unknown(i, "dynamic_startup_word")
		}
		if t == "--" || t == "-" || t == "+" {
			result.roles[i] = invocationOption
			if i+1 < len(args) {
				return finish(i + 1)
			}
			if inline {
				return unknown(i, "missing_inline_source")
			}
			result.noexec = noexec && name == "bash"
			return result
		}
		if t == "" || (t[0] != '-' && t[0] != '+') {
			return finish(i)
		}
		// Advanced ksh/ash forms are not native-qualified here. Plain file/data
		// ownership remains the existing baseline; omitted extensions stay Unknown.
		if name == "ksh" || name == "ash" {
			return unknown(i, "unqualified_profile_option")
		}
		optionIndex := i
		if strings.HasPrefix(t, "--") {
			if name != "bash" || shortSeen {
				return unknown(i, "unsupported_long_option")
			}
			switch t {
			case "--noprofile", "--norc", "--posix", "--login", "--restricted":
				result.roles[i] = invocationOption
			case "--rcfile", "--init-file":
				result.roles[i] = invocationOption
				i++
				if i >= len(args) || !downloadWordIsLiteral(args[i]) {
					return unknown(optionIndex, "unresolved_option_value")
				}
				result.roles[i] = invocationOptionValue
			default:
				return unknown(i, "unsupported_long_option")
			}
			continue
		}
		if len(t) < 2 {
			return unknown(i, "unsupported_startup_word")
		}
		shortSeen = true
		result.roles[i] = invocationOption
		for j := 1; j < len(t); j++ {
			switch t[j] {
			case 'c':
				if t[0] != '-' || inline || stdin {
					return unknown(optionIndex, "conflicting_input_mode")
				}
				inline = true
			case 's':
				if t[0] != '-' || inline {
					return unknown(optionIndex, "conflicting_input_mode")
				}
				stdin = true
			case 'n':
				noexec = t[0] == '-'
			case 'o', 'O':
				if t[j] == 'O' && name != "bash" {
					return unknown(optionIndex, "unsupported_option_operand")
				}
				// Only separate operands are admitted. An attached spelling retains the
				// entire original triggering word as Unknown instead of guessed spans.
				if name != "bash" && j+1 < len(t) {
					return unknown(optionIndex, "unsupported_attached_operand")
				}
				i++
				if i >= len(args) || !downloadWordIsLiteral(args[i]) {
					return unknown(optionIndex, "unresolved_option_value")
				}
				option := args[i].text
				if t[j] == 'O' {
					if option != "extglob" {
						return unknown(optionIndex, "unsupported_option_name")
					}
				} else {
					if !rsyncContains(strings.Fields("allexport notify noclobber errexit noglob monitor noexec nounset verbose xtrace pipefail"), option) {
						return unknown(optionIndex, "unsupported_option_name")
					}
					if option == "noexec" {
						noexec = t[0] == '-'
					}
				}
				result.roles[i] = invocationOptionValue
			case 'b':
				if name == "zsh" {
					stop = true
				} // finish this cluster before stopping later words
			case 'a', 'C', 'e', 'f', 'm', 'u', 'v', 'x', 'i', 'l', 'p':
			case 'h', 'r':
				if name != "bash" && name != "zsh" {
					return unknown(optionIndex, "unsupported_short_option")
				}
			default:
				return unknown(optionIndex, "unsupported_short_option")
			}
		}
	}
	if inline {
		return unknown(len(args), "missing_inline_source")
	}
	result.noexec = noexec && name == "bash"
	if noexec && name != "bash" {
		result.execution = invocationUncertain
	}
	return result
}

// Source builtins share the ownership contract; unsupported leading options
// cannot silently hide a candidate file in the unresolved suffix.
func readSourceInvocation(args []shWord) shellInvocation {
	p := shellInvocation{profile: "source", mode: "stdin", selected: -1, roles: make([]invocationRole, len(args)), execution: invocationEstablished}
	i := 0
	if len(args) > 0 && args[0].text == "--" {
		p.roles[0] = invocationOption
		i++
	}
	if i >= len(args) {
		return p
	}
	if !downloadWordIsLiteral(args[i]) || (i == 0 && strings.HasPrefix(args[i].text, "-")) {
		p.mode, p.reason, p.execution = "unknown", "unresolved_source_operand", invocationUncertain
		return p
	}
	p.mode, p.selected, p.roles[i] = "file", i, invocationSource
	for j := i + 1; j < len(args); j++ {
		p.roles[j] = invocationData
	}
	return p
}

// legacyInvocationProgram is a conservative candidate extraction, not proved
// argv ownership. It preserves original words/spans and prefix role exclusions.
func legacyInvocationProgram(name string, args []shWord, roles []invocationRole, reason string) []invocationProgram {
	candidate := func(index, start int) []invocationProgram {
		program := programWord(args, index, start, invocationUncertain)
		program.origin = invocationOrigin{profile: name, reason: reason}
		return []invocationProgram{program}
	}
	for i, a := range args {
		if len(roles) > i && roles[i] != invocationUnowned && roles[i] != invocationOption {
			continue
		}
		if strings.HasPrefix(a.text, "--command=") {
			return candidate(i, len("--command="))
		}
		isC := a.text == "--command" || (strings.HasPrefix(a.text, "-") && !strings.HasPrefix(a.text, "--") && strings.ContainsRune(a.text[1:], 'c'))
		if isC && i+1 < len(args) && (len(roles) <= i+1 || roles[i+1] == invocationUnowned) {
			return candidate(i+1, 0)
		}
	}
	return nil
}

// innerPrograms is the only typed shell-source adapter used by traversal.
// Unknown inline origin remains attached even when only a write is discovered.
func innerPrograms(name string, args []shWord) []invocationProgram {
	if invocationShell(name) {
		p := readShellInvocation(name, args)
		if p.mode == "unknown" {
			if p.inlineCandidate >= 0 {
				program := programWord(args, p.inlineCandidate, 0, invocationUncertain)
				program.origin = invocationOrigin{profile: name, reason: p.reason}
				return []invocationProgram{program}
			}
			return legacyInvocationProgram(name, args, p.roles, p.reason)
		}
		if p.mode == "inline" && !p.noexec {
			program := programWord(args, p.selected, 0, p.execution)
			if p.execution == invocationUncertain {
				program.origin = invocationOrigin{profile: name, reason: "uncertified_execution_mode"}
			}
			if !downloadWordIsLiteral(args[p.selected]) {
				program.certainty = invocationUncertain
				program.origin = invocationOrigin{profile: name, reason: "dynamic_inline_text"}
			}
			return []invocationProgram{program}
		}
		return nil
	}
	if agentShells[name] || name == "su" {
		return legacyInvocationProgram(name, args, nil, "legacy_inline_selection")
	}
	if name == "eval" {
		return []invocationProgram{{original: args, index: -1, assembled: wordTexts(args), certainty: invocationEstablished}}
	}
	if name == "watch" {
		return []invocationProgram{{original: args, index: -1, assembled: wordTexts(skipOptions(args, "nd")), certainty: invocationEstablished}}
	}
	return nil
}
