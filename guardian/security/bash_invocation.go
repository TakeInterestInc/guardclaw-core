// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import "strings"

type bashInvocation struct {
	known    bool
	mode     string // file, inline, stdin
	selected shWord
	noexec   bool
}

// readBashInvocation is a deliberately bounded startup grammar. Unknown is not
// an execution exemption: callers retain the legacy inline-candidate fallback.
// Only this reader selects a proven Bash file, inline program or noexec mode.
func readBashInvocation(args []shWord) bashInvocation {
	result := bashInvocation{known: true, mode: "stdin"}
	inline, stdin, shortSeen := false, false, false
	for i := 0; i < len(args); i++ {
		word, t := args[i], args[i].text
		if !downloadWordIsLiteral(word) {
			return bashInvocation{}
		}
		if t == "--" || t == "-" {
			// Both terminate startup option parsing. A following word can be
			// the -c program or file, even when it starts with '-' or '+'.
			if i+1 < len(args) {
				if inline {
					result.mode, result.selected = "inline", args[i+1]
				} else if !stdin {
					result.mode, result.selected = "file", args[i+1]
				}
			} else if inline {
				return bashInvocation{}
			}
			return result
		}
		if t == "" || (t[0] != '-' && t[0] != '+') {
			if inline {
				result.mode, result.selected = "inline", word
			} else if !stdin {
				result.mode, result.selected = "file", word
			}
			return result
		}
		if strings.HasPrefix(t, "--") {
			if shortSeen {
				return bashInvocation{}
			}
			switch t {
			case "--noprofile", "--norc", "--posix", "--login", "--restricted":
			case "--rcfile", "--init-file":
				i++
				if i >= len(args) || !downloadWordIsLiteral(args[i]) {
					return bashInvocation{}
				}
			default:
				return bashInvocation{}
			}
			continue
		}
		if len(t) < 2 {
			return bashInvocation{}
		}
		shortSeen = true
		for j := 1; j < len(t); j++ {
			switch t[j] {
			case 'c':
				if t[0] != '-' || inline || stdin {
					return bashInvocation{}
				}
				inline = true
			case 's':
				if t[0] != '-' || inline {
					return bashInvocation{}
				}
				stdin = true
			case 'n':
				result.noexec = t[0] == '-'
			case 'o', 'O':
				i++
				if i >= len(args) || !downloadWordIsLiteral(args[i]) {
					return bashInvocation{}
				}
				option := args[i].text
				if t[j] == 'O' {
					if option != "extglob" {
						return bashInvocation{}
					}
				} else {
					if !rsyncContains(strings.Fields("errexit noexec nounset pipefail verbose xtrace"), option) {
						return bashInvocation{}
					}
					if option == "noexec" {
						result.noexec = t[0] == '-'
					}
				}
			case 'e', 'f', 'u', 'v', 'x', 'i', 'l', 'p', 'r':
			default:
				return bashInvocation{}
			}
		}
		// -c enables inline mode but does not end startup option parsing.
		// Later options (including +n) apply until a non-option program or
		// explicit terminator selects the actual command operand.
	}
	if inline {
		return bashInvocation{}
	}
	return result
}
