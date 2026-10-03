# GuardClaw setup: first draft


From the repository root, run `npm run setup` to build the single Go source and
run synthetic smoke checks, then `npm start` for the offline workspace. This
requires installed Node.js 20+ and Go 1.26.6+. No npm runtime dependencies are
installed. The following host preview is a later explicit owner-guided step.
Data & safety prepares manual scanner commands and opens metadata receipts;
progress snapshots remain separate producer claims. Live mode is optional:
`npm run start:live`, select `observatory/.observatory-local/access.json`, then
connect explicitly. No host state is discovered. Do not use a real spool in tests.

Give your agent this request:

> Read AGENTS.md, docs/CAPABILITIES.md and docs/SETUP.md. Identify my host and
> exact supported tool boundary. Prepare a personal policy and a settings preview
> in this checkout. Show the diff, backup and uninstall steps before changing any
> host configuration. Do not send messages, connect accounts or request new
> permissions. Do not claim protection for tools this adapter cannot intercept.

This is an early public draft. Start with offline synthetic tests. Installing a
repo prompt gives instructions; it does not intercept tools or override host
permissions. No installer here writes your settings.

## 1. Choose the supported path

The receipt-backed adapter in this draft is **Claude Code command hooks on macOS
or Linux**. Read [capabilities and limitations](CAPABILITIES.md) first. A local
checkout does not install hooks into cloud dots or Cowork. The older Claude mod
is a separate adapter without personal policy or these receipts; do not confuse
its transcript messages with this journal. Do not pair this setup with mods that
can replace/approve tool calls: settings hooks are below mods.

For Codex, use native per-tool approvals as described in CAPABILITIES.md. Do not
install this command as a Codex hook: its `ask` response is not enforced there.

## 2. Build and test without touching your agent

Requires the Go version in go.mod. From the checkout:

```sh
go test -race ./...
go vet ./...
go build -trimpath -o bin/guardclaw-hook ./cmd/guardclaw-hook
```

Builds may download Go dependencies/toolchains if not cached. The resulting hook,
policy check, preview and receipt verifier make no network calls, send no email,
and read no account credentials. DNS remains off; the separate URLValidator
library has explicit DNS opt-in, described in the root README.

Prepare draft files in this checkout, not an agent configuration directory:

```sh
mkdir -m 700 .guardclaw
cp examples/personal-policy.json .guardclaw/policy.json
chmod 600 .guardclaw/policy.json
```

Review the policy. It uses exact host tool names, not regexes. Replace
`mcp__YOUR_SERVER__send_email` with the actual installed send tool name from your
host's tool inventory. This needs no new account connection. Do not invent a
server name, token or email address. Unknown tools default to `ask`, so a renamed
send tool still needs review unless you explicitly allow it. Set read-only tools
to `allow` only after checking their real behavior. `allow` preserves native
permissions; it never approves on the host's behalf. Known command-pattern and
protected-file denies take precedence. Recognized Bash/Monitor/MCP command
requests always require review even if the policy says `allow`.

A policy asks before **that tool call**, including an actual email send MCP tool.
It cannot identify all sends inside scripts, browsers or other tools. Reviewing a
shell call approves its whole program, which can have further effects. Policy and
binary/journal ownership and OS permissions remain part of the trust boundary.

```sh
bin/guardclaw-hook --policy "$PWD/.guardclaw/policy.json" --check-policy
bin/guardclaw-hook --preview --binary "$PWD/bin/guardclaw-hook" \
  --policy "$PWD/.guardclaw/policy.json" \
  --receipts "$PWD/.guardclaw/receipts.jsonl" > .guardclaw/hooks-preview.json
```

The preview prints three synchronous hook entries, matching all tool names:
PreToolUse, PostToolUse and PostToolUseFailure. It does not create a journal or
change host configuration. Paths must be absolute. Do not move the checkout
without regenerating and reviewing the paths. A journal is created with 0600
permissions on the first observed action; its parent must already exist.

## 3. Review and explicitly opt in

Ask your agent to show the preview and prepare a **merged candidate** for your
chosen project's `.claude/settings.local.json`, preserving every existing hook,
permission, plugin and unrelated setting. It must not overwrite your settings
with the fragment or edit user/global/managed settings as a shortcut. Resolve
conflicting hooks and tool-approving mods before relying on this adapter.

Only after you approve the exact candidate, make a uniquely named private backup
of an existing settings file and apply that candidate to the chosen project. If
no settings existed, record that fact instead. Do not overwrite previous backups.
Keep the candidate, original and the diff so uninstall is reviewable. Never add
skip-permissions settings, broad allows or disable existing security controls.

This repository provides a preview, not an automatic settings writer. You or an
explicitly authorized agent perform the reviewed merge. Existing managed policy
may forbid local hooks; retain it and report that this integration is unavailable.
Do not reconfigure an already-running agent to test this draft.

## 4. Verify the boundary before real use

Offline tests use synthetic send/lookup/delete tool events and assert real Claude
hook response shapes. They do not execute tools, send email or demonstrate a
live-host integration. Check your installed host's `/hooks` inventory and version
in a separate explicitly approved test session. Confirm that the exact send tool
is in the ask path, including renamed/unknown tools, before using real actions.
If no human can answer an ask (noninteractive run), leave the action unexecuted;
do not convert ask to allow.

Keep native exact-tool ask permissions for consequential actions as an additional
host gate. Hook timeouts, failed startup/crashes and unsupported host versions can
leave the normal permission path active without this adapter's decision. This
is not an unconditional fail-closed sandbox. Expected validation/journal errors
exit 2 and block Claude PreToolUse, but a host timeout is outside that guarantee.

Every event successfully handled by this adapter gets a durable metadata-only
receipt. Completion receipt failure cannot undo an action. A missing completion
is incomplete coverage, not evidence that nothing happened or that a user denied
it. [Verify and retain a checkpoint](RECEIPTS.md) after tests and periodically.

## 5. Uninstall or roll back

Remove only the three hook handlers whose command exactly matches your reviewed
preview, retaining other handlers/events and unrelated settings. Review this diff
before applying. Restore the original backup wholesale only if no later settings
changes would be lost; otherwise use it to prepare a selective rollback. If the
settings file did not exist before setup, remove it only when it contains no other
new settings. Restart or reload the host as its documentation requires.

Keep receipts/checkpoints for your records or remove them yourself after review.
Remove the checkout's binary/policy only after the handlers have been removed.
No credentials, services, daemons, signing keys, network permissions or account
connections were created by this adapter.

After stopping the dashboard and removing any reviewed host handlers, `npm run clean` removes only built binaries. Review policies, receipt/checkpoint files and `observatory/.observatory-local/` before deleting or retaining them yourself. No background service was installed.
