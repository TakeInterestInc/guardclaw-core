// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// withCaseFolding runs fn with pathCaseInsensitive forced to fold and restores
// the host default afterwards.
func withCaseFolding(t *testing.T, fold bool, fn func()) {
	t.Helper()
	prev := pathCaseInsensitive
	pathCaseInsensitive = fold
	defer func() { pathCaseInsensitive = prev }()
	fn()
}

// resetRegistry clears the AddProtectedPatterns / AddRootMarkers registry so
// tests do not leak registrations into each other.
func resetRegistry(t *testing.T) {
	t.Helper()
	registryMu.Lock()
	extraProtected, extraRootMarkers = nil, nil
	extraProtectedSet, extraMarkerSet = map[string]bool{}, map[string]bool{}
	registryMu.Unlock()
	t.Cleanup(func() {
		registryMu.Lock()
		extraProtected, extraRootMarkers = nil, nil
		extraProtectedSet, extraMarkerSet = map[string]bool{}, map[string]bool{}
		registryMu.Unlock()
	})
}

func TestDefaultProtectedPathsNameNoPrivateLayout(t *testing.T) {
	want := map[string]bool{
		".guardclaw/**":               true,
		".mcp.json":                   true,
		".claude/settings.json":       true,
		".claude/settings.local.json": true,
	}
	if len(DefaultProtectedPaths) != len(want) {
		t.Fatalf("DefaultProtectedPaths = %v, want only the universal config set", DefaultProtectedPaths)
	}
	for _, p := range DefaultProtectedPaths {
		if !want[p] {
			t.Errorf("unexpected default pattern %q", p)
		}
	}
	for _, p := range append(append([]string{}, DefaultProtectedPaths...), DefaultSystemProtectedPaths...) {
		if strings.HasPrefix(p, "guardian/") || strings.HasPrefix(p, "cmd/") || strings.HasPrefix(p, "infra/") {
			t.Errorf("default pattern %q names a source layout", p)
		}
	}
	if m := registeredRootMarkers(); len(m) != 0 {
		t.Errorf("root markers registered by default: %v", m)
	}
}

func TestDefaultCheckerProtectsConfigInAnyProject(t *testing.T) {
	resetRegistry(t)
	c := NewDefaultProtectedPathChecker()
	for _, p := range []string{
		".mcp.json",
		".claude/settings.json",
		".guardclaw/policy.yaml",
		"/home/a/projects/web/.mcp.json",
		"/home/a/projects/web/.claude/settings.local.json",
		"/srv/app/.guardclaw/keys/signing.key",
		"sub/dir/.claude/settings.json",
		"/home/a/proj/../proj/.mcp.json",
	} {
		if !c.IsProtected(p) {
			t.Errorf("IsProtected(%q) = false, want true", p)
		}
	}
	for _, p := range []string{
		"",
		".",
		"/",
		"README.md",
		"/home/a/projects/web/main.go",
		"/home/a/projects/web/.mcp.json.bak",
		"/home/a/guardian/security/injection.go", // no layout is protected by default
		"/home/a/mydaemon/infra/main.tf",
	} {
		if c.IsProtected(p) {
			t.Errorf("IsProtected(%q) = true, want false", p)
		}
	}
}

func TestAddProtectedPatternsAndRootMarkers(t *testing.T) {
	resetRegistry(t)
	before := NewDefaultProtectedPathChecker() // built before registration on purpose
	custom := NewProtectedPathChecker([]string{"only/this.txt"})
	path := "/home/a/src/mydaemon/internal/policy/rules.go"
	if before.IsProtected(path) {
		t.Fatal("protected before registration")
	}

	AddProtectedPatterns([]string{"internal/policy/**", "  ", "", "internal/policy/**"})
	if before.IsProtected(path) {
		t.Fatal("pattern without a root marker matched an absolute path mid-tree")
	}
	if !before.IsProtected("internal/policy/rules.go") {
		t.Fatal("registered pattern not applied to an existing default checker")
	}

	AddRootMarkers([]string{"mydaemon", "/mydaemon/", "", "/"})
	if got := registeredRootMarkers(); len(got) != 1 || got[0] != "/mydaemon/" {
		t.Fatalf("root markers = %v, want [/mydaemon/]", got)
	}
	if !before.IsProtected(path) {
		t.Fatal("registered pattern + root marker did not protect the absolute path")
	}
	if !NewDefaultWithSystemProtectedPathChecker().IsProtected(path) {
		t.Fatal("system checker ignores registered patterns")
	}
	if custom.IsProtected(path) {
		t.Fatal("explicit-pattern checker picked up registered patterns")
	}
	if pats := before.Patterns(); len(pats) != len(DefaultProtectedPaths)+1 {
		t.Fatalf("Patterns() = %v, want defaults plus one registered pattern", pats)
	}

	// A marker match must not hide the config-suffix check: before this change
	// a root-marker hit returned early and a nested .claude/settings.json under
	// the marker was not protected.
	nested := "/home/a/src/mydaemon/tools/sub/.claude/settings.json"
	if !before.IsProtected(nested) {
		t.Fatalf("IsProtected(%q) = false after marker match", nested)
	}
}

func TestProtectedPathCaseFolding(t *testing.T) {
	resetRegistry(t)
	c := NewDefaultWithSystemProtectedPathChecker()
	upper := []string{
		"/Users/a/.SSH/id_ed25519",
		"/home/a/.Ssh/config",
		"/ETC/passwd",
		"/Users/a/Library/KEYCHAINS/login.keychain-db",
		"/Users/a/proj/.MCP.json",
		"/Users/a/proj/.Claude/Settings.json",
	}
	withCaseFolding(t, true, func() {
		for _, p := range upper {
			if !c.IsProtected(p) {
				t.Errorf("fold: IsProtected(%q) = false, want true", p)
			}
		}
	})
	withCaseFolding(t, false, func() {
		for _, p := range upper {
			if c.IsProtected(p) {
				t.Errorf("no fold: IsProtected(%q) = true; a case-sensitive host treats it as a different file", p)
			}
		}
		if !c.IsProtected("/home/a/.ssh/id_rsa") {
			t.Error("exact-case path not protected")
		}
	})
	wantFold := runtime.GOOS == "darwin" || runtime.GOOS == "windows"
	if pathCaseInsensitive != wantFold {
		t.Errorf("pathCaseInsensitive = %v on %s, want %v", pathCaseInsensitive, runtime.GOOS, wantFold)
	}
}

func TestProtectedPathMacOSRootAliases(t *testing.T) {
	resetRegistry(t)
	c := NewDefaultWithSystemProtectedPathChecker()
	for _, fold := range []bool{true, false} {
		withCaseFolding(t, fold, func() {
			for _, p := range []string{
				"/private/etc/passwd",
				"/private/etc/sudoers.d/agent",
				"/private/etc/ssh/sshd_config",
				"/private/var/log/auth.log",
				"/private/var/spool/cron/root",
				"/System/Volumes/Data/private/etc/passwd",
				"/private/tmp/../etc/shadow",
			} {
				if !c.IsProtected(p) {
					t.Errorf("fold=%v: IsProtected(%q) = false, want true", fold, p)
				}
			}
			for _, p := range []string{"/private/tmp/scratch.txt", "/private/etc-notes/passwd", "/privateetc/passwd"} {
				if c.IsProtected(p) {
					t.Errorf("fold=%v: IsProtected(%q) = true, want false", fold, p)
				}
			}
		})
	}
	withCaseFolding(t, true, func() {
		if !c.IsProtected("/PRIVATE/ETC/PASSWD") {
			t.Error("case-folded alias not canonicalized")
		}
	})
}

func TestProtectedPathRegistryConcurrent(t *testing.T) {
	resetRegistry(t)
	c := NewDefaultProtectedPathChecker()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			AddProtectedPatterns([]string{fmt.Sprintf("app%d/**", i)})
			AddRootMarkers([]string{fmt.Sprintf("/root%d/", i)})
		}(i)
		go func(i int) {
			defer wg.Done()
			_ = c.IsProtected(fmt.Sprintf("/x/root%d/app%d/f", i, i))
			_ = c.Patterns()
		}(i)
	}
	wg.Wait()
	if !c.IsProtected("/x/root3/app3/f") {
		t.Fatal("registration lost under concurrency")
	}
}
