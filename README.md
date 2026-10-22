# GuardClaw

A local workspace for protection checks, mediated action receipts and progress
visibility. One checkout, one setup. The name is provisional; the repository URL
and Go module remain `TakeInterestInc/guardclaw-core`.

```sh
git clone https://github.com/TakeInterestInc/guardclaw-core.git
cd guardclaw-core
npm run setup
npm start
```

Requires installed Node.js 20+ and Go 1.26.6+. Setup builds three local tools and
runs a disposable synthetic smoke test; it never changes host settings, connects
accounts or executes test tool calls. Uncached Go builds may need dependencies.
Open **http://127.0.0.1:4317**. Stop with Ctrl+C. No runtime package install,
telemetry or account is needed. The default workspace is offline with authored
synthetic data; do not expose its loopback listener through a tunnel or proxy.

- **Checks:** Data & safety prepares an explicit local report command using
  `bin/guardclaw-report`; the browser never runs it. Advisory reports stay
  unverified and never authorize work.
- **Receipts:** Data & safety opens a deliberately selected metadata-only journal
  and optional owner-retained checkpoint. Hash consistency is separate from
  writer authenticity, execution proof and complete coverage.
- **Progress:** Owner decisions, All work and Evidence compare public-safe
  producer claims, timestamps and blockers. `npm run start:live` enables an
  explicit per-launch capability connection; `npm run demo:agent` publishes
  synthetic summaries only. No official dots/Cowork connector is included.
- **Host protection:** ask a coding agent to read [AGENTS.md](AGENTS.md) and
  [SETUP](docs/SETUP.md), identify your host/tool boundary, and prepare a concrete
  policy/settings preview. Owner approval is required before applying host
  configuration. Claude command hooks are the receipt-backed supported path;
  Codex/cloud/Cowork coverage is limited to documented native approvals.

`npm run build`, `npm run smoke` and `npm test` are repeatable local commands.
Optional installed-browser QA uses `npm run test:ui`, `test:scanner-ui`,
`test:live-ui` and `test:receipts-ui`. Go checks: `go vet ./...` and
`go test -race ./...`. [Undo](docs/SETUP.md#5-uninstall-or-roll-back): remove
reviewed host handlers before `npm run clean`, which removes only built binaries.
Policies, receipts/checkpoints and live spool remain yours to review and retain.

[Architecture decision](docs/CONSOLIDATION.md), [host capabilities](docs/CAPABILITIES.md),
[receipt limits](docs/RECEIPTS.md), [dashboard boundaries](observatory/docs/ARCHITECTURE.md),
[licenses and provenance](observatory/docs/THIRD_PARTY.md). Both source histories
are retained; the previous Dot repository remains untouched as a compatibility
source. The legacy Claude mod remains under its original path and limitations.

## Detection library and original CLI

A Go detection library and CLI for known attack patterns in the inputs an AI
agent is about to act on: a tool call, a shell command, a prompt, an MCP
message. The tiered engine returns `allow`, `escalate` or `deny`. Your code acts
on that decision; scanning alone does not intercept an agent, and `allow` does
not prove an input is safe.

```
input ──▶ Bloom filter ──▶ Aho-Corasick ──▶ composite RE2 ──▶ entropy ──▶ allow │ escalate │ deny
          (exact hash)     (literal match)   (regex)          (secrets)
                           └── run on the normalized input ──┘
```

No LLM in the detection path, no telemetry, and no network calls by default.
The one place that can resolve DNS is `security.URLValidator`, and only after
you opt in (see [Network behavior](#network-behavior)).

## Start with your agent (first draft)

Give Claude Code, Codex or Cowork the checkout and ask it to read
[AGENTS.md](AGENTS.md). It will find a [small setup workflow](docs/SETUP.md),
[the supported-host matrix](docs/CAPABILITIES.md), and an
[exact-tool personal policy template](examples/personal-policy.json).

The new offline `guardclaw-hook` adapter supports Claude Code command hooks on
macOS/Linux. It requests real host approval for configured send tools, adds
known-pattern/protected-file checks, and writes [metadata-only chained receipts](docs/RECEIPTS.md)
for each event it handles. Setup prints a preview; it never installs settings.
Synthetic tests are not live integration certification. Keep native permissions:
host hook timeouts/startup failures can leave the normal permission path active.

Codex, cloud dots and Cowork have different boundaries. Their native approval
setup is documented; this repository does not install a receipt-backed adapter
for them. The [legacy Claude mod](claude-code-mod/README.md) has no personal
policy or these receipts. Neither adapter is an arbitrary-shell containment
sandbox. We will share improvements as this draft develops.

## Install

Requires Go 1.26.6 or newer.

```sh
go install github.com/TakeInterestInc/guardclaw-core/cmd/guardclaw-scan@latest
```

Or build from a checkout:

```sh
go build -trimpath -o guardclaw-scan ./cmd/guardclaw-scan
```

## Use it as a CLI

```sh
guardclaw-scan suspicious_commands.txt
guardclaw-scan ./agent-logs/        # every file under the directory
```

Each nonblank line that does not start with `#` is scanned as one input. This is
per-line scanning, not whole-document or cross-line analysis. Findings show the
file, line, decision, severity and matched pattern. Inputs are read as text and
never executed. Directory scans follow file symlinks, so point it only at paths
you mean to read.

| Exit code | Meaning |
|---|---|
| 0 | Scan completed with no high or critical finding. Lower-severity findings can still be printed. |
| 1 | Scan completed with at least one high or critical finding. |
| 2 | Usage error, or the scan was incomplete: a missing or unreadable path, or a line over the 1 MiB limit. Errors take precedence over findings. |

In CI, treat both 1 and 2 as failure.

## Use it as a library

```go
import "github.com/TakeInterestInc/guardclaw-core/guardian/tiered"

eng, err := tiered.NewEngine(nil) // nil = defaults
if err != nil {
	return err
}
r := eng.Scan(userInput)
switch r.Decision {
case "deny":     // block the action
case "escalate": // ask a person or run another check
case "allow":    // continue with the rest of your policy
}
```

### Protected paths

`security.ProtectedPathChecker` answers "may an agent read or write this path?"
for the egress scanner and for your own tool routing. The defaults are neutral:

- `DefaultProtectedPaths`: agent and GuardClaw configuration in any project
  (`.guardclaw/**`, `.mcp.json`, `.claude/settings.json`,
  `.claude/settings.local.json`).
- `DefaultSystemProtectedPaths`: OS and home-directory secrets (`/etc/shadow`,
  `**/.ssh/**`, cloud credentials, shell history, browser stores, keychains).

An application that embeds this package registers its own files at startup:

```go
// Repo-relative globs for the files your app must keep agents away from.
security.AddProtectedPatterns([]string{"internal/policy/**", "cmd/mydaemon/**"})
// Directory names that mark your project root, so an absolute path such as
// /home/a/src/mydaemon/internal/policy/rules.go is matched as
// internal/policy/rules.go.
security.AddRootMarkers([]string{"mydaemon"})
```

Before 0.2.0 the default list named one application's source layout. It no
longer does: if your application relied on that, it has no protection for its
own files until it makes these calls (see [CHANGELOG.md](CHANGELOG.md)).

Registered patterns apply to every checker from `NewDefaultProtectedPathChecker`
and `NewDefaultWithSystemProtectedPathChecker`, including ones built before the
call; `NewProtectedPathChecker(patterns)` uses exactly the patterns you pass.
Both functions are safe for concurrent use.

Matching cleans the path first (`/tmp/../etc/passwd` is `/etc/passwd`), drops
the Windows trailing dots, spaces and `::$DATA`-style stream suffixes, uses full
Unicode case folding on macOS and Windows (`.ſsh` matches `.ssh`), and treats
`/private/etc`, `/private/var`, `/private/tmp`, `/System/Volumes/Data/...` and
`/Volumes/<name>/private/etc|var` as the macOS aliases they are.
It compares text: `IsProtectedOnDisk` also resolves symlinks for paths that
exist, and neither replaces OS file permissions.

### Literal download execution checks

`security.CheckCommandInjection` and `security.CheckAgentCommand` (including
`guardclaw-scan --stdin-command [--agent]`) also compare known explicit
`curl -o/--output` and `wget -O/--output-document` outputs with later literal
POSIX-shell file, source, and direct-path commands within the same input.
They inspect strings without fetching or executing samples. Quoted or escaped
literal filename characters retain their shell spelling; filename comparison
runs only on the original input. `CheckCommandInjectionNormalized` and the CLI
retain normalized regex matching separately. Supported Bash `-n` syntax checks
and data files passed to a separate local program keep their ordinary behavior;
other shells receive no syntax-only exemption.

This is a bounded lexical candidate check, not proof of filesystem identity or
complete download provenance. It uses the existing parser and known wrapper/
option grammar; unsupported options discard that fetch's inferred outputs.
Candidate writes persist in a shared ledger keyed by opaque filesystem-root
and current-directory tokens. Represented child shells and substitutions copy
their location while sharing prior writes, so a later child `cd` cannot erase a
write made in the parent's directory. Directory effects assign new tokens;
separate changes never imply equivalent locations. Cwd-only wrappers share
absolute candidates; changed-root wrappers isolate them. Detection is monotonic.
One bounded typed Bash startup reader selects its inline/file operand and
syntax-only mode; unknown grammar retains conservative inline analysis without
a noexec exemption. Source commands consume a supported `--` terminator.
Curl requires one literal URL and one explicit output; its own URL glob syntax
is excluded even inside shell quotes. Wget's supported single-URL `-O` form
uses its last output selection. Stdout outputs infer no file. This association
models a candidate transfer, not successful network writes or command success.
State grows with visited supported fetches and directory effects, with existing
child-depth limits; the API does not impose an input byte cap. Directory option
modes, including `pushd -n`/`popd -n`, are not precisely modeled.
Find command templates, full shell control-flow/cwd resolution,
remote/config-selected names, residual
operator-bearing words, tee flow, modules/other interpreters, filesystem and
PATH aliases, and separate invocations remain outside this boundary. A source
command can search PATH, so a matching unqualified source name is conservative.
The general `tiered.Engine.Scan` surface remains its pattern-based scanner.
Broader gaps remain tracked in [#14](https://github.com/TakeInterestInc/guardclaw-core/issues/14).

## What it detects

Baseline patterns for prompt injection, command injection, SQL injection, SSRF,
XSS, path traversal, header injection, secret and PII shapes, RAG and context
poisoning, data-exfiltration shapes, and high-entropy secret strings. The
literal and regex tiers run on a normalized copy of the input that undoes common
evasions (Unicode tricks, percent-encoding, IPv4-mapped IPv6).

Known patterns produce false positives and miss attacks. The corpus in
`testdata/corpus/` is a regression gate, not a field measurement: CI fails if more
than 1% of benign lines are denied or fewer than 95% of malicious lines get a
non-`allow` decision. See [CONTRIBUTING.md](CONTRIBUTING.md) and the
[fixture notes](testdata/corpus/README.md).

## Engine input budget

`tiered.Engine.Scan` does not impose a byte or execution-time limit. Callers
handling untrusted events should reject events larger than **4 KiB before
scanning**, and choose a smaller limit when their measured request budget needs
it. Never silently truncate an event: that can remove the malicious part while
returning an allow decision. Scan separate logical events individually rather
than concatenating a transcript or batch into one call. A caller's input limit
is still needed when using a wrapper with a larger transport limit.

The composite RE2 tier dominates the large multi-command workload in
`BenchmarkScanMultiCommand`. On one shared Linux Xeon run, 4/16/64 KiB inputs
took about 0.32/1.51/5.70 seconds per scan; these are diagnostic observations,
not latency guarantees. Measure the relevant workload on the deployment host:

```sh
go test ./guardian/tiered -run '^$' -bench=BenchmarkScanMultiCommand -benchmem
```

This advisory library does not provide a hard CPU or RSS containment boundary.

## Network behavior

- `tiered.Engine` and the `guardclaw-scan` CLI make no network calls.
- `security.URLValidator` judges URLs on their text by default. Call
  `EnableDNSResolution()` (system resolver) or `SetResolver(fn)` to also flag
  hostnames that resolve to private or loopback addresses. A check at validation
  time does not stop DNS rebinding between that check and your own connection.
- `security.ValidatePrePolicyInput` always uses a default, offline `URLValidator`.
- `security.NewEgressScanner` uses a default, offline `URLValidator` unless you
  pass one that opted in with `security.WithURLValidator`.

## Scope

This repository contains the detection engine, baseline patterns, a legacy
Claude Code mod, and the bounded offline Claude command-hook/personal-policy/
receipt adapter described above. It does not include an agent runtime, generic
action proxy, hosted control plane, account integration or cloud installer.
Nothing here depends on a hosted service. Pattern no-match, instructions and
plain receipt hashes provide neither complete protection nor writer authenticity.

## License

[Apache License 2.0](LICENSE), with [NOTICE](NOTICE). Contributions use the
[DCO](CONTRIBUTING.md). To report a security issue, see [SECURITY.md](SECURITY.md).
