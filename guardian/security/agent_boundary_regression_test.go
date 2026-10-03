// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0
package security

import "testing"

func TestAgentCwdAndExpansionMutationBoundaries(t *testing.T) {
	// Strings only: these commands are never executed.
	for _, s := range []string{
		`cd "$HOME" && rm -rf Documents`, `cd "$HOME/.claude" && cp ./replacement.json settings.json`,
		`S="$HOME/go/bin/guardclaw-scan"; cp ./fake "$S"`, `cp ./fake ${SCANNER}`, `cp ./fake "$(echo scanner)"`,
		`pushd /home/synthetic; rm -rf Documents`, `env -C /home/synthetic rm -rf Documents`, `env -C/home/synthetic rm -rf Documents`, `sudo -D/home/synthetic rm -rf Documents`, `env --chdir=/home/synthetic rm -rf Documents`,
		`chroot /home/synthetic rm -rf Documents`, `sudo -D /home/synthetic rm -rf Documents`,
		`bash -c 'cd /home/synthetic; rm -rf Documents'`, `(cd /home/synthetic && rm -rf Documents)`,
		`cd /home/synthetic; find . -name '*.pyc' -delete`, `echo data > "$DEST"`,
	} {
		if !CheckAgentCommand(s).Detected {
			t.Fatal("ambiguous mutation admitted: " + s)
		}
	}
	for _, s := range []string{`cd src && echo install`, `cd src && sed -n 1,10p README.md`, `sed -n "$RANGE" README.md`, `cd src && npm test`, `rm -rf ./build`, `cp ./input ./output`, `echo $(date)`, `npm test | tee test.log`, `go test ./... 2>&1 | tail`, `find . -name '*.pyc' -delete`} {
		if CheckAgentCommand(s).Detected {
			t.Fatal("legitimate workflow rejected: " + s)
		}
	}
}
