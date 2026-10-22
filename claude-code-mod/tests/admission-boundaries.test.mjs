// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { checkCommand, degradedVerdict, writeTargets, protectedRead } from '../hooks/rules.ts';
import { register } from '../hooks/register.ts';

// Inputs are inert strings; none of these commands is executed.
const denied = [
  'go run example.invalid/tool@v1.0.0',
  'go -C src run example.invalid/tool@latest',
  'npx uninstalled-tool', 'npx --yes uninstalled-tool',
  'npx --no-install --yes tool', 'npx --yes --no-install tool',
  'npx --no-install tool --yes', 'npx --no-install --package=evil tool',
  'npx --no-install tool --install', 'npx --no-install tool $(echo injected)',
  'go build -o ~/.ssh/id_ed25519 .', 'go test -c -o ~/.zshrc',
  'go build -o=/home/synthetic/tmp/../.zshrc .',
  'go build -o "$DEST" .', 'go -C src build -o ../.zshrc .',
  'env -C /home/synthetic go build -o .zshrc .', 'cd /home/synthetic && go build -o .zshrc .',
  'git checkout -- .', 'git checkout -f main', 'git -C repo restore .',
  'git restore main.go', 'git branch -D work', 'git branch --delete --force work',
  'git checkout README.md', 'git switch --discard-changes main', 'git branch -d -f work',
  'git switch --force-create old-work main', 'git switch --force-create=old-work main',
  'git reset --hard', 'git clean -fdx', 'git stash clear',
  'rm -rf .git', 'rm -r repo/.git/',
  'head -5 ~/.ssh/id_ed25519', 'tail ~/.netrc', 'grep -r key ~/.aws',
  'rg token /home/synthetic/.aws/', 'cat ~/.ssh/config',
  'rsync -a --delete src/ ~/', 'rsync --delete-before src/ /',
  'rsync --delete --rsh=ssh src/ ../backup/',
  'rsync --remove-source-files /home/synthetic/important.txt dist/',
  'rsync --delete src/ ~/ > log', 'rsync --delete src/ ~/ >log',
  `rsync --delete srcA/ srcB/ '2>' ~/`, `rsync --delete srcA/ srcB/ 2\\> ~/`,
];
test('mod refuses unsafe admission boundaries in both modes', () => {
  for (const command of denied) {
    assert.ok(checkCommand(command, undefined, [], '/home/synthetic'), command);
    assert.ok(degradedVerdict(command, undefined, [], '/home/synthetic'), command);
  }
});
test('explicit local workflows retain ordinary lexical admission', () => {
  for (const command of [
    'go run ./cmd/tool', 'go test ./...', 'go build -o dist/tool .',
    'npx --no-install tsc --version', 'npx --no-install @scope/tool --version',
    'git switch dev', 'git status', 'git branch -d merged-work',
    'rm -rf build', 'head -5 README.md', 'grep -r token src', 'rg --files src',
    'rsync -a --delete src/ dist/', 'rsync --remove-source-files src/file dist/',
    'rsync -a --delete src/ dist/ 2>&1',
    'rsync -a --delete src/ dist/ > log',
    'rsync --delete -e "ssh -p 2222" src/ dist/',
  ]) assert.equal(checkCommand(command), undefined, command);
  for (const command of ['npx --no-install tsc --version', 'go run ./cmd/tool',
    'go build -o dist/tool .', 'git switch main', 'head -5 README.md', 'grep -r token src']) {
    assert.equal(degradedVerdict(command), undefined, command);
  }
});
test('Go output flags are explicit write targets', () => {
  assert.deepEqual(writeTargets('go build -o dist/tool .'), ['dist/tool']);
  assert.deepEqual(writeTargets('go test -c -o=dist/test'), ['dist/test']);
});
test('credential file reads use spelling and resolved targets', async () => {
  assert.ok(protectedRead('~/.ssh/id_ed25519'));
  assert.ok(protectedRead('./innocent', '/home/synthetic', '/home/synthetic/.aws/credentials'));
  assert.equal(protectedRead('README.md'), undefined);
  const hooks = new Map();
  const on = (name, callback) => { hooks.set(name, callback); return { catch() {} }; };
  register(on, {});
  const host = {
    env: { get: async () => '/home/synthetic' },
    fs: { stat: async path => { if (path === 'unresolved' || path === '.') throw new Error('not resolved'); return { realPath: path === './alias' ? '/home/synthetic/.aws/credentials' : path }; } },
    plugin: { root: '/project/plugin' }, clock: { now: async () => Date.UTC(2026, 9, 22) },
    state: { get: async () => ({ value: undefined, version: 0 }), set: async () => ({ isSet: true }) },
    ui: { status() {}, log() {} },
  };
  let nextCalls = 0;
  const next = async () => { nextCalls++; return { ok: true }; };
  const tool = hooks.get('tool.call');
  assert.ok((await tool(host, { tool: 'Read', file_path: '~/.ssh/id_ed25519' }, next)).deny);
  assert.ok((await tool(host, { tool: 'Read', file_path: './alias' }, next)).deny);
  assert.ok((await tool(host, { tool: 'Read', file_path: 'unresolved' }, next)).deny);
  assert.deepEqual(await tool(host, { tool: 'Read', file_path: 'README.md' }, next), { ok: true });
  assert.equal(nextCalls, 1);
});
