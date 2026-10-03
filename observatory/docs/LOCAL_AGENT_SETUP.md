# Local agent producer: first draft

This is a small generic connection for an agent that can deliberately write a
prepared JSON summary on your local machine. It is not an official OpenAI Dots,
Codex, Claude Cowork, or other host connector. No account API, existing session,
prompt, memory, transcript, or log is discovered or read. Offline demo and manual
imports still need only Node 20+ and a browser, with no account or installation.

## Try it with synthetic data

From the repository root, in a terminal:

```sh
npm run start:live
```

Open the printed `http://127.0.0.1:4317` URL. In **Data & safety**, choose `observatory/.observatory-local/access.json` using **Choose local
access file**, then select **Connect local feed**. On macOS the spool directory is
hidden: in the file picker press Cmd+Shift+G and enter the project directory
followed by `/observatory/.observatory-local`. The browser keeps the capability only in memory;
its contents are never displayed. Only one live server per project is supported.

In a second terminal in the same project:

```sh
npm run demo:agent
```

The finite synthetic process publishes four updates, four seconds apart: active,
blocked with an owner choice, active with an authored decision outcome, then done
with an illustrative passing check claim. Inspect **All work**, **Owner decisions**,
and **Evidence**. The last claim is not a real executed check. This demonstrates
the local adapter, not a connected host. No actual user agent data is used.

**Disconnect local feed** stops polling and keeps the last snapshot in memory.
Reset restores the synthetic offline demo; reset/reload stop polling and clear
the browser capability. Select the current launch’s access file again to reconnect. A manual
snapshot file selection disconnects the feed before reading the selected file.
Stop the server with Ctrl+C. No daemon, login item, hook, account credentials, or persistent
access is installed. The deliberately created local snapshot and access files remain until
you remove `observatory/.observatory-local` yourself. The launch capability expires when
its server stops; the next successful launch atomically replaces the access file.
A failed occupied-port launch does not replace it. Stale browser credentials are
rejected, stop polling and require selecting the new launch’s access file. That directory is ignored by Git and
is never a static HTTP route; ignore rules do not replace inspecting data.

Use `npm start` to run the default offline server, which exposes no feed endpoint
and keeps `connect-src 'none'`. The live control is disabled in that mode.

## Ask a capable local agent to publish

Give the agent these instructions after you choose the work it may summarize:

> Use only this project's documented snapshot v1 contract in IMPORT_SCHEMA.md.
> Prepare concise public-safe task progress, owner questions and reported checks
> for the work I explicitly select. Do not read the access file or include its contents in a summary. Do not
> read/import existing agent logs,
> prompts, memories, raw tool arguments/outputs, credentials, personal data or
> private work. Do not include raw metadata or receipts. Show me the prepared
> summary first. Keep timestamps accurate; leave observation/check outcomes
> unknown or pending when there is no evidence. Source labels and any “verified”
> stage are producer claims, not authenticated execution. After I authorize
> publishing that summary, send its JSON to `node observatory/tools/local-feed.mjs publish`
> on stdin. Do not set up hooks, background services or account connections.

For an intentionally prepared local file, the operator can publish explicitly:

```sh
node observatory/tools/local-feed.mjs init
node observatory/tools/local-feed.mjs publish < prepared-safe.json
```

Or a local producer can import `localFeed` from `tools/local-feed.mjs` and call
`await localFeed().publish(JSON.stringify(preparedSnapshot))` after initialization.
Use a single producer for a project. Each publication replaces the whole snapshot;
multiple publishers have last-writer-wins behavior, with no merge or event history.
Only deliberately prepared summaries belong here. Validation detects some
credential patterns; it does not reliably redact arbitrary secrets or private
data. No automatic log-to-summary converter is included. An allowlist cannot detect
private prose or log excerpts placed in permitted text fields; preparation and
operator review remain necessary.

## Contract and limits

The transport reuses snapshot v1 unchanged: `schemaVersion`, `title`, `capturedAt`,
`tasks`, `decisions`, `evidence`. See [IMPORT_SCHEMA.md](IMPORT_SCHEMA.md) and the
synthetic `examples/snapshot.json`. It is a bounded current-state report, not an
append-only event/receipt contract. Unknown fields are rejected. Existing rules
apply: 256 KiB, 100 tasks, 100 decisions, 200 evidence records, UTC timestamps,
known enums, references, text limits, and consistency checks. Sources and URLs
are inert producer declarations. No source is fetched or followed.

The fixed `observatory/.observatory-local/snapshot.json` spool has owner-only directory/file
modes 0700/0600. Publishing validates before an atomic replacement; the server
revalidates every read and the browser validates again. Bad updates preserve the
last displayed snapshot and show an unavailable/rejected status. Freshness is
recomputed while connected, including outages; receipt time and producer capture
time are separate. Unchanged content does not advance the snapshot revision.
Changed snapshots advance it, making existing advisory scan sidecars noncurrent;
those sidecars never become task checks or approval.

The server binds only `127.0.0.1`, serves GET/HEAD only, rejects foreign Host/Origin
and cross-site Fetch Metadata, and requires the per-launch capability in a fixed request header before every
feed read or cached response. Missing/malformed/wrong/expired capabilities fail
closed without echoing credentials or reading the spool. The access file has a
strict 128-byte schema and is never served. A fresh cryptographically random
256-bit capability is published atomically to an owner-only file only after a
successful bind; it never appears in URLs, logs, screenshots or browser storage.
No CORS or network write endpoint exists. The browser polls only its own origin,
serially about every 1.5 seconds, after explicit connection. There are no path or
URL parameters, proxy fetches, commands, accounts, account secrets, or remote listeners.
The reader rejects symlinks, hardlinks, nonregular files, incorrect ownership or
permissions, invalid UTF-8, and oversized data. Disk reads are coalesced and capped
at once per second. A validated cached response can lag up to one second.

The capability blocks ordinary other-account loopback callers who cannot read
the owner-only access file. Same-user processes, privileged users, browser and
extensions can obtain that capability and remain trusted. This does not
authenticate the producer, prove claims, or isolate a compromised local account.
Do not publish private or confidential data.

This first draft targets macOS/Linux with POSIX ownership and `O_NOFOLLOW`. Windows
is unsupported and fails closed. Same-user processes, project directory, runtime,
browser and extensions are trusted; this is not isolation from a compromised
local account or an OS sandbox. Do not tunnel, reverse proxy or expose the server.

## Claimed checks and future receipts

Transport validation establishes shape and internal consistency only. Displayed
“passed”, “done”, “resolved” and “reported verified” remain unauthenticated claims.
No checks are independently run and no decisions are approved or enforced.

GuardClaw now provides separate manual receipt import in Data & safety. Read
../../docs/RECEIPTS.md. It checks canonical metadata and SHA256 chain consistency
against an optional owner-retained checkpoint. Snapshot v1 is unchanged and no
receipt becomes a task check. Neither the transport nor hashes authenticate a
producer or prove that an action ran. Without a retained checkpoint, intact-prefix
truncation or a full rewrite remains invisible.

This is a first draft. Feedback and further updates are welcome; no release
cadence, every-host support or security certification is promised.
