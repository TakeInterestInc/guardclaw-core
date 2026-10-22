// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import "testing"

func TestAmbiguousWindowsTraversalFailsClosed(t *testing.T) {
	previous := pathWindowsTraversal
	pathWindowsTraversal = true
	t.Cleanup(func() { pathWindowsTraversal = previous })
	checker := NewDefaultWithSystemProtectedPathChecker()
	for _, path := range []string{
		"C:/Users/alice/project/.. /.ssh/id_ed25519",
		"C:/Users/alice/project/.../notes.txt",
		"C:/Users/alice/project/.. ./notes.txt",
		"C:/Users/alice/project/. /notes.txt",
		"C:/Users/alice/project/..::$DATA/notes.txt",
		"C:/Users/alice/project/.. :$DATA/notes.txt",
		"/home/alice/project/.. /notes.txt",
	} {
		if !checker.IsProtected(path) {
			t.Errorf("ambiguous path %q not refused", path)
		}
	}
	for _, path := range []string{
		"C:/Users/alice/project/./notes.txt",
		"C:/Users/alice/project/../notes.txt",
		"C:/Users/alice/project/notes.txt. ",
		"C:/Users/alice/project/dot...name/notes.txt",
		"/home/alice/project/.gitignore",
	} {
		if checker.IsProtected(path) {
			t.Errorf("ordinary path %q refused", path)
		}
	}
	pathWindowsTraversal = false
	for _, path := range []string{"/tmp/.../notes.txt", "/tmp/.. /notes.txt", "/tmp/. /notes.txt"} {
		if checker.IsProtected(path) {
			t.Errorf("ordinary Unix path %q newly refused", path)
		}
	}
}
