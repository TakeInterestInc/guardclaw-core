// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"strings"
	"testing"
)

func TestRsyncForwardedDeletionBoundary(t *testing.T) {
	for _, input := range []string{
		"rsync -a --remote-option=--remove-source-files host:/important dist/",
		"rsync -a --remote-option --remove-source-files host:/important dist/",
		"rsync -a -M--remove-source-files host:/important dist/",
		"rsync -a -M --remove-source-files host:/important dist/",
		"rsync -avM--remove-source-files host:/important dist/",
		"rsync --remot=--remove-source-files host:/important dist/",
		"rsync -M--remov host:/important dist/",
		"rsync -M--delete src/ host:/important",
		"rsync --old-args -M'--info=stats2 --remove-source-files' host:/important dist/",
		"rsync -M'--info=stats2 --remove-source-files' host:/important dist/",
		"sudo rsync -M--remove-source-files host:/important dist/",
		"bash -c 'rsync -M--remove-source-files host:/important dist/'",
	} {
		for name, check := range map[string]func(string) *CommandInjectionResult{
			"strict": CheckCommandInjection, "agent": CheckAgentCommand,
		} {
			if result := check(input); !result.Detected || result.PatternName != "rsync_destructive_path" {
				t.Errorf("%s: forwarded deletion allowed: %q result=%+v", name, input, result)
			}
		}
	}
	for _, input := range []string{
		"rsync -a -M--info=stats2 host:src/ dist/",
		"rsync --remote-option=--exclude=--remove-source-files host:src/ dist/",
		"rsync -M--exclude -M--remove-source-files host:src/ dist/",
		"rsync -M--remove-source-files src/file dist/",
		"rsync -M--delete src/ dist/",
		"rsync --include=--remote-option=--remove-source-files host:src/ dist/",
		"rsync -- -M--remove-source-files host:src/ dist/",
		"rsync -M-- -M--remove-source-files host:src/ dist/",
	} {
		if result := CheckCommandInjection(input); result.Detected {
			t.Errorf("strict refused ordinary forwarded options %q (%s)", input, result.PatternName)
		}
		if result := CheckAgentCommand(input); result.Detected {
			t.Errorf("agent refused ordinary forwarded options %q (%s)", input, result.PatternName)
		}
	}
}

func TestRsyncForwardedOptionsBounded(t *testing.T) {
	options := parseRsyncDeletionOptions([]shWord{{text: strings.Repeat("-M", shMaxDepth) + "--info=stats2"}}, 0)
	if !options.unknown || !options.deleteDestination || !options.deleteSources {
		t.Fatal("excessive forwarded option nesting did not fail closed")
	}
}
