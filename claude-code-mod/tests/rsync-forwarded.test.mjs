// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { checkCommand, degradedVerdict } from '../hooks/rules.ts';

// Inert argv examples only: no rsync or remote command is executed.
test('forwarded rsync deletion keeps remote sender/receiver outside the mutation boundary', () => {
  for (const command of [
    'rsync -a --remote-option=--remove-source-files host:/important dist/',
    'rsync -a --remote-option --remove-source-files host:/important dist/',
    'rsync -a -M--remove-source-files host:/important dist/',
    'rsync -a -M --remove-source-files host:/important dist/',
    'rsync -avM--remove-source-files host:/important dist/',
    'rsync --remot=--remove-source-files host:/important dist/',
    'rsync -M--remov host:/important dist/',
    'rsync -M--delete src/ host:/important',
    "rsync --old-args -M'--info=stats2 --remove-source-files' host:/important dist/",
    "rsync -M'--info=stats2 --remove-source-files' host:/important dist/",
    'sudo rsync -M--remove-source-files host:/important dist/',
  ]) {
    assert.equal(checkCommand(command)?.rule, 'rsync_destructive_path', command);
    assert.ok(degradedVerdict(command), command);
  }
});
test('forwarded option values and plain local deletions keep ordinary behavior', () => {
  for (const command of [
    'rsync -a -M--info=stats2 host:src/ dist/',
    'rsync --remote-option=--exclude=--remove-source-files host:src/ dist/',
    'rsync -M--exclude -M--remove-source-files host:src/ dist/',
    'rsync -M--remove-source-files src/file dist/',
    'rsync -M--delete src/ dist/',
    'rsync --include=--remote-option=--remove-source-files host:src/ dist/',
    'rsync -- -M--remove-source-files host:src/ dist/',
    'rsync -M-- -M--remove-source-files host:src/ dist/',
  ]) {
    assert.equal(checkCommand(command), undefined, command);
    // Scanner-missing mode may still refuse rsync by its existing allowlist.
    assert.notEqual(degradedVerdict(command)?.rule, 'rsync_destructive_path', command);
  }
});

test('forwarded option nesting has a fail-closed work bound', () => {
  assert.equal(checkCommand(`rsync ${'-M'.repeat(16)}--info=stats2 host:src/ dist/`)?.rule, 'rsync_destructive_path');
});

