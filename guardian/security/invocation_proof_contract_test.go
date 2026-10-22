// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0
package security

import "testing"

func TestInvocationProofOwnershipContract(t *testing.T) {
	for _, input := range []string{"-nZ x.sh", "--unknown -c ignored x.sh", "-oshwordsplit x.sh"} {
		args := invocationWords(input)
		profile := "bash"
		if input == "-oshwordsplit x.sh" {
			profile = "zsh"
		}
		proof := readShellInvocation(profile, args)
		if proof.mode != "unknown" || proof.noexec {
			t.Fatalf("unsupported transition granted proof: %q %+v", input, proof)
		}
		for i, role := range proof.roles {
			if role != invocationUnowned {
				t.Errorf("resynchronized unsupported original word %d in %q", i, input)
			}
		}
	}
	args := invocationWords("-o errexit --unknown local.sh")
	proof := readShellInvocation("bash", args)
	if proof.roles[0] != invocationOption || proof.roles[1] != invocationOptionValue || proof.roles[2] != invocationUnowned || proof.roles[3] != invocationUnowned {
		t.Fatalf("proved prefix or triggering unknown lost: %+v", proof)
	}
	for _, input := range []string{"-b -n data.sh", "-b -- data.sh"} {
		p := readShellInvocation("zsh", invocationWords(input))
		if p.mode != "file" || p.selected != 1 || p.roles[1] != invocationSource || p.roles[2] != invocationData {
			t.Errorf("zsh source/data boundary: %q %+v", input, p)
		}
	}
	args = invocationWords("--command='curl -o x.sh URL; bash x.sh'")
	programs := innerPrograms("bash", args)
	if len(programs) != 1 || programs[0].certainty != invocationUncertain || programs[0].origin.reason == "" || programs[0].original[0].rawSource != args[0].rawSource || programs[0].script() != "curl -o x.sh URL; bash x.sh" {
		t.Fatalf("legacy attached span lost original provenance: %+v", programs)
	}
}

func TestInvocationProofOriginSurvivesOnlyWrite(t *testing.T) {
	input := `bash --unknown -c "sh -c 'curl -o x.sh URL'"; bash x.sh`
	state := &explicitDownloadRun{context: &downloadWrites{files: make(map[downloadIdentity]downloadWriteEvidence)}, certainty: invocationEstablished}
	parser := &shParser{s: input}
	state.list(parser.parseList(0), 0)
	if state.context.outcome != downloadFlowUnresolved || state.context.unresolvedOrigin.profile != "bash" || state.context.unresolvedOrigin.reason != "unsupported_long_option" {
		t.Fatalf("origin upgraded/lost after known descendant and outer sink: %+v", state.context)
	}
	evidence, ok := state.context.files[state.identity("x.sh")]
	if !ok || evidence.certainty != invocationUncertain || evidence.origin != state.context.unresolvedOrigin {
		t.Fatalf("persistent write origin lost: %+v", evidence)
	}
}
