// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"path/filepath"
	"strings"
)

// DefaultProtectedPaths defines file paths that GuardClaw must prevent
// external agents from reading. These cover the security core, threat model,
// CLI internals, and sensitive configuration.
var DefaultProtectedPaths = []string{
	// Core security modules.
	"guardian/security/**",
	"guardian/threat/**",
	"guardian/anomaly/**",
	"guardian/selfprotect/**",
	"guardian/capability/**",
	"guardian/policy/engine.go",
	// CLI binaries.
	"cmd/guardclaw/**",
	"cmd/guardclaw-cloud/**",
	"cmd/guardclaw-mcp/**",
	"cmd/guardclaw-shell/**",
	"cmd/guardclaw-sign/**",
	"cmd/guardclaw-seed/**",
	"cmd/guardclaw-watchdog/**",
	"cmd/guardclaw-menubar/**",
	// Protocol and API internals.
	"mcp/server.go",
	"mcp/handlers.go",
	"mcp/gateway.go",
	"httpapi/server.go",
	// Threat model and infrastructure.
	"agent-guardian-threat-model*",
	"infra/**",
	// GuardClaw configuration (universal — present in all installations).
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

// ProtectedPathChecker determines whether a file path belongs to GuardClaw's
// protected surface area. Paths are matched using glob-style patterns with
// support for ** (any depth) and * (single segment wildcard).
type ProtectedPathChecker struct {
	patterns []string
}

// NewProtectedPathChecker creates a checker with the given glob patterns.
// Patterns use forward slashes and support ** for recursive matching.
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

// NewDefaultProtectedPathChecker creates a checker with DefaultProtectedPaths.
// Does NOT include DefaultSystemProtectedPaths — existing contract preserved
// so callers that care only about GuardClaw-internal files see no change.
func NewDefaultProtectedPathChecker() *ProtectedPathChecker {
	return NewProtectedPathChecker(DefaultProtectedPaths)
}

// NewDefaultWithSystemProtectedPathChecker returns a checker covering both
// DefaultProtectedPaths (repo-internal sensitive files) and
// DefaultSystemProtectedPaths (OS / user-home secrets and tokens).
//
// Used by executors/bash_analyzer.go so the v0.7.0 structural analyzer
// blocks protected-path reads that target real system secrets by default,
// not just GuardClaw internals. Callers that want only one of the two
// lists keep using the narrower constructors.
func NewDefaultWithSystemProtectedPathChecker() *ProtectedPathChecker {
	combined := make([]string, 0, len(DefaultProtectedPaths)+len(DefaultSystemProtectedPaths))
	combined = append(combined, DefaultProtectedPaths...)
	combined = append(combined, DefaultSystemProtectedPaths...)
	return NewProtectedPathChecker(combined)
}

// IsProtected returns true if the given path matches any protected pattern.
//
// Normalization is applied in two forms so that patterns can either carry
// a leading slash (matches absolute paths, e.g. /etc/passwd against
// system-protected patterns) or be repo-relative (matches after
// normalizePath strips the absolute prefix, e.g. guardian/security/**).
//
// filepath.Clean is applied before matching so traversal segments (../)
// are collapsed — `cat /tmp/../etc/passwd` normalizes to /etc/passwd
// before the pattern check.
func (p *ProtectedPathChecker) IsProtected(path string) bool {
	clean := filepath.Clean(filepath.ToSlash(strings.TrimSpace(path)))
	if clean == "" || clean == "." {
		return false
	}

	// Check two forms against the pattern set:
	//   1. The cleaned path as-is (matches absolute-style patterns).
	//   2. The repo-normalized form (existing behavior — strips prefix,
	//      applies config-critical suffix fallback).
	forms := []string{clean}
	if relative := normalizePath(clean); relative != "" && relative != clean {
		forms = append(forms, relative)
	}

	for _, form := range forms {
		for _, pattern := range p.patterns {
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

// Patterns returns a copy of the current pattern list.
func (p *ProtectedPathChecker) Patterns() []string {
	out := make([]string, len(p.patterns))
	copy(out, p.patterns)
	return out
}

// configCriticalSuffixes are path suffixes that must be protected regardless
// of which project directory GuardClaw is installed in. These are matched
// by suffix when repo-root markers are not found in the absolute path.
//
// SECURITY: This prevents agents from bypassing self-protection by writing
// to config files in projects outside the agent-guardian repo.
var configCriticalSuffixes = []string{
	"/.claude/settings.local.json",
	"/.claude/settings.json",
	"/.mcp.json",
	"/.guardclaw/",
}

// normalizePath converts an input path to a relative, forward-slash path for
// matching. It strips common absolute prefixes (/Users/..., /home/..., etc.)
// and tries to extract the project-relative portion.
func normalizePath(path string) string {
	path = filepath.ToSlash(path)
	path = strings.TrimSpace(path)

	// Strip leading slash for absolute paths. We try to find the
	// repository-relative portion by looking for known root markers.
	if strings.HasPrefix(path, "/") {
		// Look for the repo root marker in the path.
		markers := []string{
			"/agent-guardian/",
			"/guardclaw/",
		}
		for _, marker := range markers {
			if idx := strings.Index(path, marker); idx != -1 {
				path = path[idx+len(marker):]
				return path
			}
		}

		// Config-critical paths: match by suffix so that .claude/settings.local.json
		// is protected in ANY project directory, not just agent-guardian.
		for _, suffix := range configCriticalSuffixes {
			if idx := strings.Index(path, suffix); idx != -1 {
				// Return the suffix without leading slash to match patterns.
				return path[idx+1:]
			}
		}

		// Fallback: strip everything up to and including the last known
		// workspace-style prefix. This handles /Users/x/project/...
		// by taking the path as-is minus the leading slash.
		path = strings.TrimPrefix(path, "/")
	}

	return path
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
