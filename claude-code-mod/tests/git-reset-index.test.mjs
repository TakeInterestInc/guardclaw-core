// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { checkCommand, degradedVerdict } from '../hooks/rules.ts';

test('index and worktree reset modes require a human operation', () => {
  for (const command of [
    'git reset --merge HEAD', 'git reset --mer HEAD',
    'git reset --keep HEAD', 'git reset --mixed HEAD',
    'git reset HEAD', 'git reset', 'git reset -- tracked.txt',
    'git reset --patch tracked.txt', 'git reset -N HEAD',
    'git reset --soft --merge HEAD',
    'git -C repo reset --merge HEAD', 'sudo git reset --merge HEAD',
  ]) {
    assert.equal(checkCommand(command)?.rule, 'git_discard_work', command);
    assert.ok(degradedVerdict(command), command);
  }
  for (const command of ['git reset --soft HEAD~1', 'git reset -q --soft HEAD', 'git status', 'git switch dev']) {
    assert.equal(checkCommand(command), undefined, command);
  }
  // Degraded mode's preexisting Git subcommand allowlist still refuses reset.
  assert.ok(degradedVerdict('git reset --soft HEAD~1'));
});

test('isolated native Git oracle demonstrates staged-content loss and soft preservation', t => {
  const root = mkdtempSync(join(tmpdir(), 'guardclaw-fixed-reset-oracle-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  // Every repository and byte below is a fixed test fixture, never user work.
  // Preserve fixed staged/unstaged bytes outside the repository before reset.
  for (const mode of ['--merge', '--mer', '--mixed', '--keep', '--soft']) {
    const cwd = join(root, mode.slice(2)); mkdirSync(cwd);
    const git = (...args) => execFileSync('git', ['-c', 'user.name=Fixed Fixture', '-c', 'user.email=fixture@example.invalid', ...args], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    const file = join(cwd, 'tracked.txt');
    git('init', '-q'); writeFileSync(file, 'fixed base\n'); git('add', 'tracked.txt'); git('commit', '-qm', 'fixed base');
    writeFileSync(file, 'fixed unique staged\n'); git('add', 'tracked.txt');
    const staged = git('show', ':tracked.txt');
    const work = mode === '--merge' || mode === '--mer' ? staged : 'fixed distinct unstaged\n';
    writeFileSync(file, work);
    writeFileSync(join(root, mode.slice(2) + '.staged-backup'), staged);
    writeFileSync(join(root, mode.slice(2) + '.work-backup'), work);
    git('reset', mode, 'HEAD');
    if (mode === '--soft') {
      assert.equal(git('show', ':tracked.txt'), staged);
      assert.equal(readFileSync(file, 'utf8'), work);
    } else {
      assert.equal(git('show', ':tracked.txt'), 'fixed base\n', mode);
      assert.equal(readFileSync(file, 'utf8'), mode === '--merge' || mode === '--mer' ? 'fixed base\n' : work, mode);
    }
  }
});
