# Receipt contract v1

A receipt records what this adapter observed. It is not an email delivery proof,
proof of human approval, complete host audit log, signature or authenticity
claim. Hash chaining detects mutation relative to a trusted history/checkpoint.
Anyone who can rewrite the journal can recompute a replacement chain.

The new Claude command-hook adapter journals every valid decision event before
emitting its response and each completion event it receives. The older mod and
other hosts do not produce this journal. Host startup failures/timeouts, skipped
or disabled hooks, unmediated tool paths, crashes and denied/canceled calls may
leave coverage incomplete. Missing completion does not establish the action's
outcome. A successful PostToolUse observation means the host reported success,
not that every external effect is known.

## Schema

| Field | Meaning |
|---|---|
| `schema` | `guardclaw.receipt.v1` |
| `chain_id` | Random 32 lowercase hex characters on first append; not a key or identity |
| `sequence` | Positive integer starting at 1; append order, not causal/tool-start order |
| `prev_hash` | Previous record hash; 64 zero characters at genesis |
| `timestamp` | UTC RFC3339Nano timestamp set by local writer clock |
| `host` | `claude-code` for this adapter |
| `event` | `decision` or `completion` |
| `action_id` | SHA256 of compact JSON `[session_id,tool_use_id]` from host correlation IDs; random 32-hex ID if either absent |
| `tool` | Configured exact tool name; unknown names become `unmapped` |
| `decision` | `allow`, `deny`, `ask` for decisions; `none` for completions |
| `rule` | Fixed code, such as `personal_policy`, `shell_review`, `command_pattern`, `protected_path`, `adapter_path`, `invalid_tool_input`, `host_observation` |
| `outcome` | `pending` for decisions; `success`/`failure` for observed completions |
| `redaction` | `metadata-only.v1` |
| `hash` | Lowercase SHA256 hex of canonical record with `hash` omitted |

An ask is a request to the host, not a record of user consent. The adapter emits
no `permissionDecision: allow`; its allow means normal host permission flow.
Decision and completion share action_id when host IDs are present. Without
IDs there is no reliable event pairing. Session/tool-use hashes expose
linkability and can be guessed for low-entropy identifiers. They are not privacy
protection or hashes of action content. Do not pass secrets as correlation IDs.

## Redaction and canonical bytes

The adapter constructs the above allowlisted metadata before serialization.
Arguments, commands, email recipients/body, file paths, outputs, errors and
credentials are omitted entirely; it does not hash them as a substitute for
redaction. No arbitrary reason strings are persisted. Policy tool names must be
public identifiers, not secrets. Metadata itself can be sensitive: hashing does
not encrypt it, and no confidentiality guarantee is made.

Canonical encoding is exactly Go `encoding/json` compact object encoding with
**all schema fields present**, keys sorted lexicographically, UTF-8, no floats,
integers in decimal. There is no Unicode normalization. String escapes include
JSON controls, quotes/backslashes, lowercase `\u003c`, `\u003e`, `\u0026` for
`<`, `>`, `&`, and `\u2028`/`\u2029`. Other non-ASCII is literal UTF-8. Only the
`hash` field is omitted from the bytes to hash. The journal adds one LF after the
canonical complete record; that LF is not hashed. Verification rejects unknown
fields, duplicate fields, invalid metadata, noncanonical whitespace/escaping,
partial lines, mismatched hashes, chain IDs, previous hashes and sequences.

Cross-language vectors:

- [canonical-v1.json](../guardian/receipts/testdata/canonical-v1.json): exact
  canonical bytes and SHA256, including a non-ASCII/escaping encoder vector
  that is deliberately invalid as receipt metadata.
- [verification-v1.json](../guardian/receipts/testdata/verification-v1.json):
  valid chains, mutation, unknown/duplicate fields, duplicate sequence, reorder,
  partial lines and trusted-anchor truncation cases.

## Persistence and trust

Hook input and policy JSON are bounded to 1 MiB. Oversized events are rejected
without a receipt because the adapter cannot safely parse a complete event;
post-tool rejection does not undo the action. This must be labeled incomplete
coverage, not a clean or successful check.

macOS/Linux persistence uses a private regular file (0600), rejects a final-path
symlink, and locks the opened journal with flock. Contention is bounded to about
one second, then fails. Each append verifies the full existing chain, writes a
single canonical line and fsyncs the file and parent directory before returning.
This requires local-filesystem sync support; an error blocks the pre-tool response. Partial writes/crashes leave
an incomplete journal that subsequent appends reject; there is no silent repair,
truncate, rotation or loss of history. The maximum journal size is 64 MiB; archive
and start a new explicitly identified chain before reaching it. Verification
cost grows with history; host deadlines can still interrupt it. Windows
persistence is unsupported and returns an error.

The containing directory, executable, policy and journal must be owned/protected
outside agent-controlled tools. A final-file symlink check does not secure the
parent directories. Direct file-tool protection in this adapter is best effort,
not a filesystem sandbox. Other processes can ignore locks. File removal and
replacement, forged host events or an owner/root attacker remain outside the
hash chain's authenticity guarantee.

## Verification and retained checkpoints

```sh
bin/guardclaw-hook --verify --receipts /absolute/path/receipts.jsonl
bin/guardclaw-hook --verify --receipts /absolute/path/receipts.jsonl \
  --checkpoint /absolute/path/trusted-checkpoint.json
```

The first command prints the current `{chain_id,sequence,hash}`. Retain that
checkpoint yourself in independently controlled storage and use it for later
verification. Do not overwrite an old checkpoint automatically with the journal's
current tip. No signing keys, persistent credential access or external connection
are created. A trusted checkpoint can appear anywhere in a valid extended chain;
missing or changed checkpoint fails verification. Without one, deleting an
intact suffix, deleting the whole journal, or rewriting all records cannot be
detected. A checkpoint in the same writable directory can be rewritten too and
is not an independent root of trust. Empty unanchored verification means only
zero observed records, not complete coverage. Consumers must label this as
`internal consistency checked; externally anchored history unavailable`.

## GuardClaw workspace

Data & safety can manually open a deliberately selected metadata journal and an
optional independently retained checkpoint. The browser port runs the canonical
Go vectors, rejects noncanonical/unknown metadata, and checks the SHA256 chain.
It accepts at most 1 MiB / 2,000 records (Go CLI: 64 MiB), shows the last 50 and
keeps all data only in memory. Reset/reload or Remove receipt data discards it.
Imports never reach the server. No filesystem auto-discovery or live journal
endpoint exists. Select only tool identifiers you are authorized to display.

An ask receipt proves only the recorded request, not that the owner approved.
Completion is a host-reported observation. Hash consistency is neither a signature
nor full coverage; keep a trusted checkpoint separately. A checkpoint selected
alongside an untrusted journal does not authenticate either file. Snapshot checks
and action authority are unchanged by importing receipts.
