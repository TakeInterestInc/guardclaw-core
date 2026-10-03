# GuardClaw Core: agent onboarding

This is public, standalone first-draft code. Read README.md and
[docs/CAPABILITIES.md](docs/CAPABILITIES.md) before proposing setup; then follow
[docs/SETUP.md](docs/SETUP.md). Do not claim a prompt installs a runtime guard.

- Identify the user's host/version and actual tool boundary. Ask-before-send must
  be an exact send-tool host permission, not a shell regex or a promise in text.
- Prepare policy and settings previews in the checkout. Changing host settings
  requires explicit approval of a concrete diff, a private backup and an uninstall
  plan. Preserve all existing permissions/hooks and managed policy. Never weaken
  host restrictions. Do not change a running agent for a test.
- Do not connect accounts, create credentials/signing keys, send email/messages,
  or request broader access as part of setup. Synthetic tests execute no tools.
- Keep network off in runtime checks; optional URL DNS resolution stays opt-in.
- Receipts cover only observed mediated events. Read docs/RECEIPTS.md. Do not
  persist raw inputs, outputs, paths, errors, secrets or their hashes. Plain hash
  chains do not authenticate writers; truncation needs a retained trusted anchor.
- Legacy Claude mod has separate limitations and no chained receipts/personal
  policy. Do not advertise unsupported Codex/cloud/Cowork adapters.
- Use public/original code only. Do not import proprietary runtime instructions,
  customer data, credentials or hosted/private product code.

Validation for Go changes: gofmt, go vet ./..., go test -race ./.... The existing
mod test kit depends on host version; plugin validation alone is not execution
coverage. Never label synthetic tests as live-host integration evidence.
