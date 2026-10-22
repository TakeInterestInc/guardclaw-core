// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMountedAliasesRetainSymlinkTraversal(t *testing.T) {
	resetRegistry(t)
	checker := NewDefaultWithSystemProtectedPathChecker()
	for _, fold := range []bool{false, true} {
		withCaseFolding(t, fold, func() {
			for _, path := range []string{
				"/Volumes/Boot/etc/../../etc/passwd",
				"/Volumes/Boot/./etc/../../etc/shadow",
				"/Volumes/Boot/private/etc/../../etc/passwd",
				"/Volumes/Boot/var/../../etc/passwd",
				"/Volumes/Boot/etc/../var/log/auth.log",
				"/Volumes/Boot/etc/../../var/log/auth.log",
			} {
				if !checker.IsProtected(path) {
					t.Errorf("fold=%v: mounted alias traversal %q not protected", fold, path)
				}
			}
			for _, path := range []string{
				"/Volumes/USB/etc/../../notes.txt",
				"/Volumes/USB/etc/../notes.txt",
				"/tmp/etc/../../notes.txt",
				"/etc/../notes.txt",
			} {
				if checker.IsProtected(path) {
					t.Errorf("fold=%v: ordinary path %q protected", fold, path)
				}
			}
		})
	}
	// Extra alias forms may add protection but must not replace a custom
	// policy's existing lexical interpretation.
	custom := NewProtectedPathChecker([]string{"/Volumes/etc/passwd"})
	if !custom.IsProtected("/Volumes/Boot/etc/../../etc/passwd") {
		t.Fatal("mounted alias form displaced custom lexical protection")
	}
}

func TestMountedAliasTraversalSymlinkFixture(t *testing.T) {
	// Reproduce the boot-volume etc -> private/etc shape using synthetic
	// files only. Keep .. in the raw spelling; filepath.Join would erase it.
	volume := t.TempDir()
	if err := os.MkdirAll(filepath.Join(volume, "private", "etc"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("private", "etc"), filepath.Join(volume, "etc")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	want := filepath.Join(volume, "private", "etc", "passwd")
	if err := os.WriteFile(want, []byte("synthetic fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(volume + "/etc/../../etc/passwd")
	if err != nil || resolved != want {
		t.Fatalf("symlink traversal resolved to %q, %v; want %q", resolved, err, want)
	}
	if got := mountedAliasTraversal("/Volumes/Boot/etc/../../etc/passwd", false); got != "/etc/passwd" {
		t.Fatalf("mounted alias traversal = %q, want /etc/passwd", got)
	}
}
