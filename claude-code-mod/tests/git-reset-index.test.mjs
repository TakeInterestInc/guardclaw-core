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
    'git reset --soft "$MODE"', 'git reset --soft {--hard,HEAD}',
    'git reset --soft HEAD -- tracked.txt',
    'git --config-env fixture.value=PATH reset',
    'git --config-env=fixture.value=PATH reset --mixed HEAD',
    'git -C repo --config-env fixture.value=PATH reset --merge HEAD',
    'git --config-env fixture.value=PATH -c advice.detachedHead=false reset --keep HEAD',
    'git --config-env fixture.value=PATH checkout -- tracked.txt',
    'git --unknown-global-flag operand reset --merge HEAD',
    'git --config-env',

  ]) {
    assert.equal(checkCommand(command)?.rule, 'git_discard_work', command);
    assert.ok(degradedVerdict(command), command);
  }
  for (const command of ['git reset --soft HEAD~1', 'git reset -q --soft HEAD', 'git reset -h', 'git status', 'git switch dev',
    'git --config-env fixture.value=PATH status',
    'git --config-env=fixture.value=PATH reset --soft HEAD~1',
    'git -c fixture.value=reset status', 'git -cfixture.value=reset status',
    'git --git-dir repo/.git --work-tree repo status',
    'git -C repo -- reset --soft HEAD',
]) {
    assert.equal(checkCommand(command), undefined, command);
  }
  // Degraded mode's preexisting Git subcommand allowlist still refuses reset.
  assert.ok(degradedVerdict('git reset --soft HEAD~1'));
});

test('isolated native Git oracle demonstrates staged-content loss and soft preservation', t => {
  const root = mkdtempSync(join(tmpdir(), 'guardclaw-fixed-reset-oracle-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const config = join(root, 'empty-gitconfig'); writeFileSync(config, '');
  const templates = join(root, 'empty-templates'); mkdirSync(templates);
  // Do not inherit GIT_DIR, GIT_WORK_TREE, alternate index/object paths,
  // global config or user hooks that could redirect this fixture elsewhere.
  const env = {
    PATH: process.env.PATH ?? '/usr/bin:/bin',
    ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}),
    HOME: root, XDG_CONFIG_HOME: root, GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: config, GIT_CONFIG_SYSTEM: config,
    GIT_TEMPLATE_DIR: templates, GIT_TERMINAL_PROMPT: '0',
  };
  // Every repository and byte below is a fixed test fixture, never user work.
  // Preserve fixed staged/unstaged bytes outside the repository before reset.
  for (const [index, { mode, globals = [] }] of [
    ...['--merge', '--mer', '--mixed', '--keep', '--soft'].map(mode => ({ mode })),
    { mode: '--mixed', globals: ['--config-env', 'fixture.value=PATH'] },
    { mode: '--merge', globals: ['--config-env=fixture.value=PATH'] },
  ].entries()) {
    const fixture = `${index}-${mode.slice(2)}`;
    const cwd = join(root, fixture); mkdirSync(cwd);
    const git = (...args) => execFileSync('git', ['-c', 'user.name=Fixed Fixture', '-c', 'user.email=fixture@example.invalid', ...args], { cwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    const file = join(cwd, 'tracked.txt');
    git('init', '-q'); writeFileSync(file, 'fixed base\n'); git('add', 'tracked.txt'); git('commit', '-qm', 'fixed base');
    writeFileSync(file, 'fixed unique staged\n'); git('add', 'tracked.txt');
    const staged = git('show', ':tracked.txt');
    const work = mode === '--merge' || mode === '--mer' ? staged : 'fixed distinct unstaged\n';
    // Keep merge's staged-only case untouched after add: even an identical
    // rewrite can make its index stat stale and legitimately abort --merge.
    if (work !== staged) writeFileSync(file, work);
    writeFileSync(join(root, fixture + '.staged-backup'), staged);
    writeFileSync(join(root, fixture + '.work-backup'), work);
    git(...globals, 'reset', mode, 'HEAD');
    if (mode === '--soft') {
      assert.equal(git('show', ':tracked.txt'), staged);
      assert.equal(readFileSync(file, 'utf8'), work);
    } else {
      assert.equal(git('show', ':tracked.txt'), 'fixed base\n', mode);
      assert.equal(readFileSync(file, 'utf8'), mode === '--merge' || mode === '--mer' ? 'fixed base\n' : work, mode);
    }
  }
});
