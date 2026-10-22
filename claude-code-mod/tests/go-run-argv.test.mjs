// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { checkCommand, degradedVerdict } from '../hooks/rules.ts';

// Inert commands only. Native Go's argv behavior is independently checked
// using a fixed local printf fixture, never a remote module.
test('go run acquisition ends at its package or consecutive Go source operands', () => {
  for (const command of [
    'go run ./cmd/tool user@example.com',
    "go run ./cmd/tool '*'",
    'go run ./cmd/tool --package=example.invalid/tool@v1',
    'go run main.go helper.go user@example.com',
    "go run main.go helper.go '*'",
    'go run -- ./cmd/tool user@example.com',
    'go run -ldflags=-X=main.label=user@example.com ./cmd/tool',
    "go run -ldflags '-X main.label=user@example.com' ./cmd/tool",
    'go run user@example.com.go',
  ]) assert.equal(checkCommand(command), undefined, command);
  assert.equal(degradedVerdict('go run ./cmd/tool user@example.com'), undefined);
});

test('build-option operands cannot conceal a versioned or unresolved package', () => {
  for (const command of [
    'go run example.invalid/tool@v1',
    'go run -tags integration example.invalid/tool@latest',
    'go run -ldflags=-X=main.label=ok example.invalid/tool@v1',
    'go run -- example.invalid/tool@v1',
    'go run "$PACKAGE" user@example.com',
    'go run *.go user@example.com',
    'go run -unknown-option value ./cmd/tool',
  ]) assert.equal(checkCommand(command)?.rule, 'remote_execution', command);
});
