# GuardClaw observatory component

Use the [one product README](../README.md) and [setup](../docs/SETUP.md) from the
repository root: `npm run setup`, then `npm start`. This folder contains the
read-only progress/check/receipt workspace; it is part of GuardClaw.

The snapshot v1 contract, loopback route/header names and owner-only spool remain
compatible. Scanner source and fixtures now live once at the repository root.
Commands shown by the dashboard run from that root. `npm run start:live` requires
explicit selection of `observatory/.observatory-local/access.json`; the producer
CLI remains `node observatory/tools/local-feed.mjs init` or `publish`.

Original Dot history/license notices and bundled fonts are preserved. See
[architecture](docs/ARCHITECTURE.md), [snapshot schema](docs/IMPORT_SCHEMA.md),
[local feed](docs/LOCAL_AGENT_SETUP.md), [reports](docs/SCANNER_REPORTS.md) and
[third-party notices](docs/THIRD_PARTY.md). This is a generic local component,
not an official dots/Cowork connector or a task execution runtime.
