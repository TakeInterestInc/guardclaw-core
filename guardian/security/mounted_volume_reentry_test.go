// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMountedAliasTraversalPreservesVolumeReentry(t *testing.T) {
	resetRegistry(t)
	checker := NewDefaultWithSystemProtectedPathChecker()
	for _, fold := range []bool{false, true} {
		withCaseFolding(t, fold, func() {
			for _, input := range []string{
				"/Volumes/Boot/etc/../../../Boot/etc/passwd",
				"/Volumes/Boot/private/etc/../../../Boot/etc/passwd",
				"/Volumes/Boot/var/../../../Boot/etc/passwd",
				"/Volumes/Boot/etc/../../../../Volumes/Boot/etc/passwd",
				"/Volumes/Boot/etc/../../../../Volumes/Other/etc/passwd",
			} {
				if got := mountedAliasTraversal(input, fold); got != "/etc/passwd" {
					t.Errorf("fold=%v: alias %q = %q, want /etc/passwd", fold, input, got)
				}
				if !checker.IsProtected(input) {
					t.Errorf("fold=%v: alias %q not protected", fold, input)
				}
			}
			for _, input := range []string{
				"/Volumes/Boot/etc/../../../Boot/notes.txt",
				"/Volumes/Boot/etc/../../../Boot/private/notes.txt",
				"/Volumes/Boot/etc/../../../../Volumes/Other/notes.txt",
			} {
				if checker.IsProtected(input) {
					t.Errorf("fold=%v: ordinary reentry %q protected", fold, input)
				}
			}
		})
	}
	withCaseFolding(t, true, func() {
		if !checker.IsProtected("/vOLUMES/bOOT/eTC/../../../bOOT/eTC/passwd") {
			t.Fatal("folded volume reentry not protected")
		}
	})
}

func TestMountedVolumeReentryPhysicalOracle(t *testing.T) {
	root := t.TempDir()
	volume := filepath.Join(root, "Volumes", "Boot")
	for _, name := range []string{"etc", "var"} {
		if err := os.MkdirAll(filepath.Join(volume, "private", name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("private", name), filepath.Join(volume, name)); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
	}
	want := filepath.Join(volume, "private", "etc", "passwd")
	if err := os.WriteFile(want, []byte("synthetic fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{
		"/Volumes/Boot/etc/../../../Boot/etc/passwd",
		"/Volumes/Boot/private/etc/../../../Boot/etc/passwd",
		"/Volumes/Boot/var/../../../Boot/etc/passwd",
		"/Volumes/Boot/etc/../../../../Volumes/Boot/etc/passwd",
	} {
		// Concatenation retains parent components for the OS resolver.
		// filepath.Join would clean away the symlink traversal first.
		resolved, err := filepath.EvalSymlinks(root + input)
		if err != nil || resolved != want {
			t.Fatalf("physical reentry %q resolved to %q, %v; want %q", input, resolved, err, want)
		}
		for _, fold := range []bool{false, true} {
			if got := mountedAliasTraversal(input, fold); got != "/etc/passwd" {
				t.Errorf("fold=%v: modeled reentry = %q, want /etc/passwd", fold, got)
			}
		}
	}
}
