// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"strings"
	"testing"
)

// Ported from GuardClaw main #421 (RedactStringExcept). The token is a
// FAKE, built by concatenation so it is never a literal credential.
func TestRedactStringExceptKeepsListedTypes(t *testing.T) {
	d := NewPIIDetector()
	token := "ghp_" + "FAKEFAKEFAKE0123456789abcdefghijklmn"
	in := "curl http://10.1.2.3/x?token=" + token

	out := d.RedactStringExcept(in, PIIIPAddress)
	if strings.Contains(out, token) {
		t.Fatalf("token survived: %q", out)
	}
	if !strings.Contains(out, "10.1.2.3") {
		t.Fatalf("kept type was redacted: %q", out)
	}
	if all := d.RedactString(in); strings.Contains(all, "10.1.2.3") || strings.Contains(all, token) {
		t.Fatalf("RedactString should still redact every type: %q", all)
	}
	if got := d.RedactStringExcept("ls -la", PIIIPAddress); got != "ls -la" {
		t.Fatalf("clean input changed: %q", got)
	}
	// With nothing kept it behaves exactly like RedactString.
	if a, b := d.RedactStringExcept(in), d.RedactString(in); a != b {
		t.Fatalf("RedactStringExcept() with no keep list = %q, RedactString = %q", a, b)
	}
}
