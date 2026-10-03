# GuardClaw Core

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
