// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import "testing"

func TestRsyncDeletionBoundary(t *testing.T) {
	for _, input := range []string{
		"rsync -a --delete src/ ~/", "rsync --delete-before src/ /",
		"rsync --delete-during src/ /home/synthetic/", "rsync --del src/ ../backup/",
		"rsync --delete-excluded src/ .git/", "rsync --delete-missing-args src/ ~/.ssh/",
		"rsync --remove-source-files /home/synthetic/important.txt dist/",
		"rsync --remove-source-files src/ ../important.txt dist/",
		"rsync --remove-source-f /home/synthetic/important.txt dist/",
		`rsync --delete -e "ssh -p 2222" src/ /`,
		"rsync --delete src/ / --log-file dist/log", "rsync --delete src/ / --unknown dist/",
		"rsync --delete src/ $DEST", "sudo rsync --delete src/ ~/",
		"rsync --delete src/ ~/ > log", "rsync --delete src/ ~/ >log",
		`rsy""nc --delete src/ /etc`, `rsyn\c --delete src/ /etc`,
		`rsync --delete srcA/ srcB/ '2>' ~/`, `rsync --delete srcA/ srcB/ 2\> ~/`,
		"bash -c 'rsync --delete src/ ~/'",
	} {
		if !CheckCommandInjection(input).Detected {
			t.Errorf("strict admitted %q", input)
		}
		if !CheckAgentCommand(input).Detected {
			t.Errorf("agent admitted %q", input)
		}
	}
	for _, input := range []string{
		"rsync -a --delete src/ dist/", "rsync --delete-after ./empty/ ./build/",
		`rsync --delete -e "ssh -p 2222" src/ dist/`,
		"rsync --delete --log-file log.txt src/ dist/",
		"rsync --delete src/ dist/ --log-file log.txt",
		"rsync --remove-source-files src/file dist/", "rsync -a src/ ~/backup/",
		"rsync -a -- src/ --delete", "rsync --include=--delete src/ dist/",
	} {
		if CheckCommandInjection(input).Detected {
			t.Errorf("strict refused ordinary transfer %q", input)
		}
		if CheckAgentCommand(input).Detected {
			t.Errorf("agent refused ordinary transfer %q", input)
		}
	}
	if CheckAgentCommand("rsync -a --delete src/ dist/ 2>&1").Detected {
		t.Error("agent refused a plain transfer with an FD copy")
	}
	if CheckAgentCommand("rsync -a --delete src/ dist/ > log").Detected {
		t.Error("agent refused a plain transfer with a local log redirect")
	}
}
