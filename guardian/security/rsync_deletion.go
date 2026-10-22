// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import "strings"

// Rsync deletion is a filesystem mutation, even though the ordinary rsync
// rules describe egress. Open the same literal wrappers as agent mode and
// require every deleted side to be a plain path inside the working folder.
func matchRsyncDeletion(input string) bool {
	for _, line := range []string{input} {
		p := &shParser{s: line}
		commands := p.parseList(0)
		bad := false
		visitCommands(commands, 0, func(name string, args []shWord) {
			if name == "rsync" && rsyncDeletionUnsafe(args) {
				bad = true
			}
		})
		if bad || (p.overflow && strings.Contains(line, "rsync")) {
			return true
		}
	}
	return false
}

var rsyncValueOptions = strings.Fields(`rsh rsync-path include exclude filter include-from exclude-from
files-from password-file log-file log-file-format out-format backup-dir suffix temp-dir partial-dir
compare-dest copy-dest link-dest chmod chown usermap groupmap remote-option address port sockopts
bwlimit stop-after stop-at timeout contimeout max-delete max-size min-size block-size modify-window
checksum-seed checksum-choice compress-choice compress-level skip-compress iconv info debug outbuf`)

var rsyncFlagOptions = strings.Fields(`archive recursive relative no-relative times perms owner group
devices specials hard-links links copy-links safe-links copy-unsafe-links copy-dirlinks keep-dirlinks
verbose quiet checksum compress progress partial inplace append append-verify existing ignore-existing
ignore-errors force prune-empty-dirs numeric-ids dry-run update backup whole-file one-file-system
itemize-changes stats human-readable protect-args secluded-args old-args msgs2stderr blocking-io
non-blocking-io fsync mkpath omit-dir-times omit-link-times atimes open-noatime crtimes executability
super fake-super no-super acls xattrs no-delete`)

func rsyncContains(options []string, option string) bool {
	for _, candidate := range options {
		if candidate == option {
			return true
		}
	}
	return false
}

type rsyncDeletionOptions struct {
	operands          []string
	deleteDestination bool
	deleteSources     bool
	unknown           bool
}

// Forwarded -M arguments form one remote argv stream. Parse them together so
// an exclude/filter value cannot be mistaken for a destructive option.
func parseRsyncDeletionOptions(args []shWord, depth int) rsyncDeletionOptions {
	modern := parseRsyncDeletionOptionsMode(args, depth, false)
	legacy := parseRsyncDeletionOptionsMode(args, depth, true)
	modern.deleteDestination = modern.deleteDestination || legacy.deleteDestination
	modern.deleteSources = modern.deleteSources || legacy.deleteSources
	modern.unknown = modern.unknown || legacy.unknown
	return modern
}

// Older rsync and modern --old-args split spaces in forwarded arguments. The
// scanner cannot attest the host version, so inspect both documented forms.
// Keep each interpretation separate through recursion: two bounded walks,
// rather than multiplying alternate interpretations at every nesting level.
func parseRsyncDeletionOptionsMode(args []shWord, depth int, legacy bool) rsyncDeletionOptions {
	if depth >= shMaxDepth {
		return rsyncDeletionOptions{deleteDestination: true, deleteSources: true, unknown: true}
	}
	var result rsyncDeletionOptions
	var forwarded []shWord
	endOptions := false
	for i := 0; i < len(args); i++ {
		a := args[i].text
		if !endOptions && a == "--" {
			endOptions = true
			continue
		}
		if !endOptions && strings.HasPrefix(a, "--") {
			option := strings.TrimPrefix(a, "--")
			name, value, hasValue := strings.Cut(option, "=")
			if name == "del" || strings.HasPrefix(name, "delete") || (len(name) >= 3 && strings.HasPrefix("delete", name)) {
				result.deleteDestination = true
			} else if strings.HasPrefix(name, "remove-source") || strings.HasPrefix(name, "remove-sent") || (strings.HasPrefix("remove-source-files", name) && len(name) >= len("remov")) {
				result.deleteSources = true
			} else if len(name) >= len("remot") && strings.HasPrefix("remote-option", name) {
				if !hasValue {
					i++
					if i >= len(args) {
						result.unknown = true
						continue
					}
					value = args[i].text
				}
				forwarded = append(forwarded, shWord{text: value})
			} else if rsyncContains(rsyncValueOptions, name) {
				if !hasValue {
					i++
					if i >= len(args) {
						result.unknown = true
					}
				}
			} else if !hasValue && !rsyncContains(rsyncFlagOptions, name) {
				// A new option might consume the final word. Do not mistake its
				// value for a safe destination after an unsafe real destination.
				result.unknown = true
			}
			continue
		}
		if !endOptions && strings.HasPrefix(a, "-") && len(a) > 1 {
			for j := 1; j < len(a); j++ {
				if a[j] == 'M' {
					value := a[j+1:]
					if value == "" {
						i++
						if i >= len(args) {
							result.unknown = true
							break
						}
						value = args[i].text
					}
					forwarded = append(forwarded, shWord{text: value})
					break
				}
				if strings.ContainsRune("efBT@", rune(a[j])) {
					if j == len(a)-1 {
						i++
						if i >= len(args) {
							result.unknown = true
						}
					}
					break
				}
				if !strings.ContainsRune("0acrtplogDHSxvqnuzRLKEOWJAXIbChsUy", rune(a[j])) {
					result.unknown = true
				}
			}
			continue
		}
		result.operands = append(result.operands, a)
	}
	if len(forwarded) > 0 {
		if legacy {
			var split []shWord
			for _, word := range forwarded {
				for _, field := range strings.FieldsFunc(word.text, func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' }) {
					split = append(split, shWord{text: field})
				}
			}
			forwarded = split
		}
		remote := parseRsyncDeletionOptionsMode(forwarded, depth+1, legacy)
		result.deleteDestination = result.deleteDestination || remote.deleteDestination
		result.deleteSources = result.deleteSources || remote.deleteSources
		result.unknown = result.unknown || remote.unknown
	}
	return result
}

func rsyncDeletionUnsafe(args []shWord) bool {
	options := parseRsyncDeletionOptions(rsyncWithoutRedirects(args), 0)
	deleteDestination, deleteSources, unknown := options.deleteDestination, options.deleteSources, options.unknown
	operands := options.operands
	if !deleteDestination && !deleteSources {
		return false
	}
	if unknown || len(operands) < 2 {
		return true
	}
	plain := func(path string) bool {
		if !isPlainRelPath(path) {
			return false
		}
		for _, part := range strings.Split(path, "/") {
			if part == ".git" {
				return false
			}
		}
		return !NewDefaultWithSystemProtectedPathChecker().IsProtected(path)
	}
	if deleteDestination && !plain(operands[len(operands)-1]) {
		return true
	}
	if deleteSources {
		for _, source := range operands[:len(operands)-1] {
			if !plain(source) {
				return true
			}
		}
	}
	return false
}

// The shared shell parser retains redirection text in words. A log filename
// must never be mistaken for rsync's destination, including when strictLine
// receives the parser's dangling `2>` half of an FD copy.
func rsyncWithoutRedirects(args []shWord) []shWord {
	out := make([]shWord, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i].text
		if strings.ContainsAny(args[i].rawSource, "'\"\\") {
			out = append(out, args[i])
			continue
		}
		at := strings.IndexAny(a, "<>")
		if at < 0 || strings.Contains(a, "<(") || strings.Contains(a, ">(") {
			out = append(out, args[i])
			continue
		}
		prefix := a[:at]
		digits := prefix != ""
		for _, r := range prefix {
			if r < '0' || r > '9' {
				digits = false
			}
		}
		if prefix != "" && !digits {
			out = append(out, shWord{text: prefix})
		}
		if strings.TrimLeft(a[at:], "<>&|") == "" && i+1 < len(args) {
			i++
		}
	}
	return out
}

func rsyncDeletionResult() *CommandInjectionResult {
	return &CommandInjectionResult{Detected: true, Score: 1, Confidence: 1,
		Category: CmdCategoryDestructive, PatternName: "rsync_destructive_path",
		Reason: "Command injection detected: rsync deletion outside a plain in-tree path"}
}
