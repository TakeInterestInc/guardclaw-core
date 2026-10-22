// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestCommandBoundaryKeepsRawFilenameIdentity(t *testing.T) {
	for _, input := range []string{
		"curl -o x%2Esh https://example.invalid/x && bash x.sh",
		"curl -o 'ｘ.sh' https://example.invalid/x && bash x.sh",
	} {
		var out, diagnostics bytes.Buffer
		code := runCommand(strings.NewReader(input), &out, &diagnostics, true)
		var verdict commandVerdict
		if err := json.Unmarshal(out.Bytes(), &verdict); err != nil {
			t.Fatal(err)
		}
		if code != 0 || verdict.Decision != "allow" {
			t.Errorf("raw identity changed: %q code=%d verdict=%+v", input, code, verdict)
		}
	}
}
