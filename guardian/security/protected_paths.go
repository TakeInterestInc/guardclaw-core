// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	pathpkg "path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// DefaultProtectedPaths is the neutral, universal default: agent and
// GuardClaw configuration files that exist in any installation, matched in any
// project directory. It deliberately names no source layout. An application
// that embeds this package and has its own files to shield (its source tree,
// policy files, threat model, deployment config) registers them at runtime
// with AddProtectedPatterns and, when it matches repo-relative globs against
// absolute paths, AddRootMarkers.
var DefaultProtectedPaths = []string{
	".guardclaw/**",
	".mcp.json",
	".claude/settings.json",
	".claude/settings.local.json",
}

// DefaultSystemProtectedPaths covers operating-system and cross-project
// sensitive files that agents must not be able to exfiltrate. These
// patterns use leading-/ for Linux/Unix system paths and **/ prefixes
// for user-home patterns that should match in any home directory.
//
// Curated to avoid false positives from common dev workflows. Bare
// **/*.key and **/*.pem are intentionally excluded (developer projects
// use those extensions for non-secret files) — sensitive key material
// is covered more precisely by **/.ssh/** and /etc/ssl/private/**.
//
// Callers combine this with DefaultProtectedPaths via
// NewDefaultWithSystemProtectedPathChecker.
var DefaultSystemProtectedPaths = []string{
	// Linux / Unix system identity and auth.
	"/etc/passwd",
	"/etc/shadow",
	"/etc/gshadow",
	"/etc/group",
	"/etc/sudoers",
	"/etc/sudoers.d/**",
	"/etc/ssh/**",
	"/etc/ssl/private/**",
	"/etc/pam.d/**",
	"/etc/security/**",
	"/etc/systemd/**",
	"/etc/init.d/**",
	"/etc/cron.d/**",
	"/etc/cron.allow",
	"/etc/cron.deny",
	"/etc/hosts.allow",
	"/etc/hosts.deny",
	"/etc/fstab",
	"/etc/mtab",
	// Logs that leak secrets and session state.
	"/var/log/auth.log",
	"/var/log/secure",
	"/var/log/wtmp",
	"/var/log/btmp",
	"/var/log/lastlog",
	"/var/spool/cron/**",
	// Root home and procfs introspection.
	"/root/**",
	"/proc/*/environ",
	"/proc/*/mem",
	"/proc/*/maps",
	"/proc/self/root/**",

	// User home — secrets & tokens.
	"**/.ssh/**",
	"**/.gnupg/**",
	"**/.aws/credentials",
	"**/.aws/config",
	"**/.kube/config",
	"**/.kube/cache/**",
	"**/.docker/config.json",
	"**/.gcloud/**",
	"**/.config/gcloud/**",
	"**/.azure/**",
	"**/.terraform.d/credentials.tfrc.json",
	"**/.npmrc",
	"**/.pypirc",
	"**/.netrc",
	"**/.git-credentials",
	"**/.config/git/credentials",
	"**/.gem/credentials",
	"**/.cargo/credentials",
	"**/.m2/settings.xml",
	// Shell + tool history (commonly contains tokens and secrets in practice).
	"**/.bash_history",
	"**/.zsh_history",
	"**/.psql_history",
	"**/.python_history",
	"**/.mysql_history",
	"**/.sqlite_history",
	"**/.rediscli_history",
	"**/.irb_history",
	// Anthropic / Claude configs (cross-project).
	"**/.anthropic/**",
	"**/.claude/credentials*",

	// macOS-specific targets.
	"**/Library/Keychains/**",
	"**/Library/Application Support/com.apple.TCC/**",
	"**/Library/Application Support/Google/Chrome/**/Cookies",
	"**/Library/Application Support/Google/Chrome/**/Login Data",
	"**/Library/Application Support/Firefox/**/cookies.sqlite",
	"**/Library/Application Support/Firefox/**/key4.db",
	"**/Library/Application Support/Firefox/**/logins.json",
	"**/Library/Cookies/**",
	"**/Library/Containers/com.apple.mail/**",
	"**/Library/Messages/chat.db",
}

// pathCaseInsensitive reports whether path comparisons fold case. macOS
// (APFS/HFS+ default) and Windows (NTFS) resolve ~/.SSH and ~/.ssh to the same
// directory, so an exact-case match would let a differently-cased path slip
// past a protected pattern. A variable rather than a constant so tests can
// exercise both behaviors on any host.
var pathCaseInsensitive = runtime.GOOS == "darwin" || runtime.GOOS == "windows"

// macOSRootAliases are prefixes that resolve to the same file as the path with
// the prefix replaced. /etc, /var and /tmp are symlinks into /private on macOS,
// and /System/Volumes/Data is the firmlinked data volume. They are applied on
// every OS: on Linux the aliased forms are not real system paths, so treating
// them as protected costs nothing and keeps behavior host-independent.
var macOSRootAliases = []struct{ prefix, replacement string }{
	{"/system/volumes/data/", "/"},
	{"/private/etc/", "/etc/"},
	{"/private/var/", "/var/"},
	{"/private/tmp/", "/tmp/"},
}

// Runtime registry for embedding applications. Guarded by registryMu; read on
// every IsProtected call so registrations take effect for checkers that already
// exist (an EgressScanner built before AddProtectedPatterns still sees them).
var (
	registryMu        sync.RWMutex
	extraProtected    []string
	extraRootMarkers  []string
	extraProtectedSet = map[string]bool{}
	extraMarkerSet    = map[string]bool{}
)

// AddProtectedPatterns registers additional glob patterns that every checker
// built with NewDefaultProtectedPathChecker or
// NewDefaultWithSystemProtectedPathChecker treats as protected, including
// checkers created before the call. Use it to shield an embedding
// application's own files, for example:
//
//	security.AddProtectedPatterns([]string{"internal/policy/**", "cmd/mydaemon/**"})
//
// Patterns use forward slashes and the same glob syntax as
// NewProtectedPathChecker. Empty and duplicate entries are ignored. Safe for
// concurrent use. Checkers built with NewProtectedPathChecker use only the
// patterns they were given.
func AddProtectedPatterns(patterns []string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	for _, p := range patterns {
		p = filepath.ToSlash(strings.TrimSpace(p))
		if p == "" || extraProtectedSet[p] {
			continue
		}
		extraProtectedSet[p] = true
		extraProtected = append(extraProtected, p)
	}
}

// AddRootMarkers registers directory names that mark the root of a project
// whose files are protected by repo-relative patterns. When an absolute path
// contains a marker, the part after it is also matched against the patterns,
// so with marker "/mydaemon/" the path /home/a/src/mydaemon/internal/policy/x.go
// is checked as internal/policy/x.go. A marker is one or more path segments;
// leading and trailing slashes are added when missing. Empty entries and the
// bare root "/" are ignored. Applies to every checker. Safe for concurrent use.
func AddRootMarkers(markers []string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	for _, m := range markers {
		m = strings.Trim(filepath.ToSlash(strings.TrimSpace(m)), "/")
		if m == "" {
			continue
		}
		m = "/" + m + "/"
		if extraMarkerSet[m] {
			continue
		}
		extraMarkerSet[m] = true
		extraRootMarkers = append(extraRootMarkers, m)
	}
}

func registeredPatterns() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return append([]string(nil), extraProtected...)
}

func registeredRootMarkers() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return append([]string(nil), extraRootMarkers...)
}

// ProtectedPathChecker determines whether a file path belongs to a protected
// surface. Paths are matched using glob-style patterns with support for **
// (any depth) and * (single segment wildcard).
type ProtectedPathChecker struct {
	patterns []string
	// withRegistered adds the AddProtectedPatterns registry at match time.
	withRegistered bool
}

// NewProtectedPathChecker creates a checker with exactly the given glob
// patterns. Patterns use forward slashes and support ** for recursive matching.
func NewProtectedPathChecker(patterns []string) *ProtectedPathChecker {
	clean := make([]string, 0, len(patterns))
	for _, p := range patterns {
		p = filepath.ToSlash(strings.TrimSpace(p))
		if p != "" {
			clean = append(clean, p)
		}
	}
	return &ProtectedPathChecker{patterns: clean}
}

// NewDefaultProtectedPathChecker creates a checker with DefaultProtectedPaths
// plus anything registered through AddProtectedPatterns. It does not include
// DefaultSystemProtectedPaths.
func NewDefaultProtectedPathChecker() *ProtectedPathChecker {
	c := NewProtectedPathChecker(DefaultProtectedPaths)
	c.withRegistered = true
	return c
}

// NewDefaultWithSystemProtectedPathChecker returns a checker covering
// DefaultProtectedPaths, DefaultSystemProtectedPaths (OS and user-home secrets
// and tokens) and anything registered through AddProtectedPatterns. Callers
// that want only one of the lists use the narrower constructors.
func NewDefaultWithSystemProtectedPathChecker() *ProtectedPathChecker {
	combined := make([]string, 0, len(DefaultProtectedPaths)+len(DefaultSystemProtectedPaths))
	combined = append(combined, DefaultProtectedPaths...)
	combined = append(combined, DefaultSystemProtectedPaths...)
	c := NewProtectedPathChecker(combined)
	c.withRegistered = true
	return c
}

// IsProtected returns true if the given path matches any protected pattern.
//
// The path is cleaned first, so traversal segments are collapsed
// (/tmp/../etc/passwd becomes /etc/passwd). On macOS and Windows the
// comparison ignores case. macOS root aliases (/private/etc, /private/var,
// /private/tmp, /System/Volumes/Data) are folded to their canonical form.
//
// Each pattern is then tried against several forms of the path: the cleaned
// path itself (for absolute patterns such as /etc/passwd), the path without
// its leading slash, the part after any registered root marker, and, when the
// path contains a config-critical suffix such as /.mcp.json, the part from that
// suffix on, so agent configuration is protected in any project directory.
func (p *ProtectedPathChecker) IsProtected(path string) bool {
	clean := cleanPath(path)
	if clean == "" || clean == "." || clean == "/" {
		return false
	}
	fold := pathCaseInsensitive
	if fold {
		clean = strings.ToLower(clean)
	}
	clean = canonicalRoot(clean, fold)

	patterns := p.patterns
	if p.withRegistered {
		if extra := registeredPatterns(); len(extra) > 0 {
			patterns = append(append([]string(nil), p.patterns...), extra...)
		}
	}

	for _, form := range pathForms(clean, fold) {
		for _, pattern := range patterns {
			if fold {
				pattern = strings.ToLower(pattern)
			}
			if matchGlob(pattern, form) {
				return true
			}
		}
	}
	return false
}

// IsProtectedOnDisk extends IsProtected with a symlink-resolution step.
// If the literal path is not protected but exists on disk and resolves
// (via filepath.EvalSymlinks) to a protected target, returns true.
//
// Existence-checked — if the path does not exist, returns whatever
// IsProtected returned (no free negative result). Safe to call on
// hostile input; no writes are performed.
func (p *ProtectedPathChecker) IsProtectedOnDisk(path string) bool {
	if p.IsProtected(path) {
		return true
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	if resolved == path {
		return false
	}
	return p.IsProtected(resolved)
}

// Patterns returns a copy of the current pattern list, including registered
// patterns for the default checkers.
func (p *ProtectedPathChecker) Patterns() []string {
	out := make([]string, len(p.patterns))
	copy(out, p.patterns)
	if p.withRegistered {
		out = append(out, registeredPatterns()...)
	}
	return out
}

// configCriticalSuffixes are path suffixes that must be protected regardless
// of which project directory they sit in.
//
// SECURITY: This prevents agents from bypassing self-protection by writing
// to config files in projects other than the one being guarded.
var configCriticalSuffixes = []string{
	"/.claude/settings.local.json",
	"/.claude/settings.json",
	"/.mcp.json",
	"/.guardclaw/",
}

// cleanPath trims, converts separators to forward slashes and collapses
// . and .. segments. pathpkg.Clean is used rather than filepath.Clean so the
// result keeps forward slashes on Windows too.
func cleanPath(p string) string {
	p = strings.TrimSpace(filepath.ToSlash(strings.TrimSpace(p)))
	if p == "" {
		return ""
	}
	return pathpkg.Clean(p)
}

// canonicalRoot folds macOS root aliases to their canonical form, repeating
// until none applies so chained aliases such as
// /System/Volumes/Data/private/etc resolve to /etc. The input is already
// lowercased when fold is true.
func canonicalRoot(p string, fold bool) string {
	for changed := true; changed; {
		changed = false
		for _, a := range macOSRootAliases {
			prefix := a.prefix
			if !fold {
				// Prefixes are stored lowercase; on a case-sensitive host only
				// the real macOS spelling is an alias.
				prefix = macOSCase(prefix)
			}
			if strings.HasPrefix(p, prefix) {
				p = a.replacement + strings.TrimPrefix(p, prefix)
				changed = true
			}
		}
	}
	return p
}

// macOSCase returns the on-disk spelling of a lowercase alias prefix.
func macOSCase(lower string) string {
	if lower == "/system/volumes/data/" {
		return "/System/Volumes/Data/"
	}
	return lower
}

// pathForms returns the distinct forms of a cleaned path that patterns are
// matched against. See IsProtected.
func pathForms(clean string, fold bool) []string {
	forms := []string{clean}
	add := func(f string) {
		if f == "" {
			return
		}
		for _, existing := range forms {
			if existing == f {
				return
			}
		}
		forms = append(forms, f)
	}

	rooted := clean
	if strings.HasPrefix(clean, "/") {
		add(strings.TrimPrefix(clean, "/"))
		for _, marker := range registeredRootMarkers() {
			if fold {
				marker = strings.ToLower(marker)
			}
			if idx := strings.Index(clean, marker); idx != -1 {
				add(clean[idx+len(marker):])
			}
		}
	} else {
		rooted = "/" + clean
	}

	for _, suffix := range configCriticalSuffixes {
		if idx := strings.Index(rooted, suffix); idx != -1 {
			add(rooted[idx+1:])
		}
	}
	return forms
}

// matchGlob matches a pattern against a path. It supports:
//   - * matches any non-separator characters in a single path segment
//   - ** matches zero or more path segments (recursive)
//   - ? matches a single non-separator character
func matchGlob(pattern, path string) bool {
	// Split both into segments.
	patParts := strings.Split(pattern, "/")
	pathParts := strings.Split(path, "/")
	return matchParts(patParts, pathParts)
}

func matchParts(pattern, path []string) bool {
	pi, pj := 0, 0
	for pi < len(pattern) && pj < len(path) {
		if pattern[pi] == "**" {
			// ** can match zero or more path segments.
			// Skip consecutive ** patterns.
			for pi < len(pattern) && pattern[pi] == "**" {
				pi++
			}
			if pi >= len(pattern) {
				// ** at end matches everything.
				return true
			}
			// Try matching remaining pattern against every suffix of path.
			for k := pj; k <= len(path); k++ {
				if matchParts(pattern[pi:], path[k:]) {
					return true
				}
			}
			return false
		}
		// Normal segment match using filepath.Match.
		matched, err := filepath.Match(pattern[pi], path[pj])
		if err != nil || !matched {
			return false
		}
		pi++
		pj++
	}
	// Consume trailing ** patterns.
	for pi < len(pattern) && pattern[pi] == "**" {
		pi++
	}
	return pi >= len(pattern) && pj >= len(path)
}
