// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

// Compatibility shape for existing private tests/callers; all semantics come
// from the shared ownership reader rather than a second Bash parser.
type bashInvocation struct {
	known    bool
	mode     string
	selected shWord
	noexec   bool
}

func readBashInvocation(args []shWord) bashInvocation {
	proof := readShellInvocation("bash", args)
	if proof.mode == "unknown" {
		return bashInvocation{}
	}
	result := bashInvocation{known: true, mode: proof.mode, noexec: proof.noexec}
	if proof.selected >= 0 {
		result.selected = args[proof.selected]
	}
	return result
}
