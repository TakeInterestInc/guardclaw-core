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

func rsyncDeletionUnsafe(args []shWord) bool {
	args = rsyncWithoutRedirects(args)
	var operands []string
	deleteDestination, deleteSources, unknown, endOptions := false, false, false, false
	for i := 0; i < len(args); i++ {
		a := args[i].text
		if !endOptions && a == "--" {
			endOptions = true
			continue
		}
		if !endOptions && strings.HasPrefix(a, "--") {
			option := strings.TrimPrefix(a, "--")
			name, _, hasValue := strings.Cut(option, "=")
			if name == "del" || strings.HasPrefix(name, "delete") || (len(name) >= 3 && strings.HasPrefix("delete", name)) {
				deleteDestination = true
			} else if strings.HasPrefix(name, "remove-source") || strings.HasPrefix(name, "remove-sent") || (strings.HasPrefix("remove-source-files", name) && len(name) >= len("remov")) {
				deleteSources = true
			} else if rsyncContains(rsyncValueOptions, name) {
				if !hasValue {
					i++
					if i >= len(args) {
						unknown = true
					}
				}
			} else if !hasValue && !rsyncContains(rsyncFlagOptions, name) {
				// A new option might consume the final word. Do not mistake its
				// value for a safe destination after an unsafe real destination.
				unknown = true
			}
			continue
		}
		if !endOptions && strings.HasPrefix(a, "-") && len(a) > 1 {
			for j := 1; j < len(a); j++ {
				if strings.ContainsRune("efBMT@", rune(a[j])) {
					if j == len(a)-1 {
						i++
						if i >= len(args) {
							unknown = true
						}
					}
					break
				}
				if !strings.ContainsRune("0acrtplogDHSxvqnuzRLKEOWJAXIbChsUy", rune(a[j])) {
					unknown = true
				}
			}
			continue
		}
		operands = append(operands, a)
	}
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
