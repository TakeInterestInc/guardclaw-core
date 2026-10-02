# Changelog

The version lives in `VERSION`. Releases are not tagged yet; this file records
what changes between source releases.

## 0.2.0 (unreleased)

### Breaking: the default protected-path list is smaller

`DefaultProtectedPaths` no longer lists any application's source layout. It
now holds only agent and GuardClaw configuration that exists in every
installation: `.guardclaw/**`, `.mcp.json`, `.claude/settings.json` and
`.claude/settings.local.json`. No root markers are registered by default.

If you embed this package and relied on the old list to shield your own
source tree, binaries, policy files or service files, that protection is gone
until you register it yourself. Call these once at startup:

```go
security.AddProtectedPatterns([]string{"internal/policy/**", "cmd/mydaemon/**"})
security.AddRootMarkers([]string{"mydaemon"})
```

An embedder that calls neither loses protection for its own files. See
"Protected paths" in the README.

### Path matching

- Case-insensitive on macOS and Windows with full Unicode case folding, so
  `.ſsh` (U+017F) and `.Kube` with a Kelvin sign (U+212A) match `.ssh` and
  `.kube`.
- macOS aliases fold to the canonical path: `/private/etc`, `/private/var`,
  `/private/tmp`, `/System/Volumes/Data/...` and `/Volumes/<name>/private/etc`
  or `/private/var`.
- Windows-equivalent names fold too: trailing dots and spaces on a segment,
  and alternate-stream suffixes such as `::$DATA`.
- Every occurrence of a root marker or config-critical suffix is tried; a
  marker match no longer skips the config-suffix check.
- Bounded work: a path longer than 4096 bytes, or one with more than 16
  marker/suffix occurrences, is treated as protected (fail closed). Patterns
  are case-folded and split once, when the checker is built or the pattern is
  registered.

### Self-protection command checks

Pattern names are unchanged. The regex patterns match the guard's full names
inside one command. A new `security.MatchSelfProtection` runs after them in
`CheckCommandInjection` and in the tiered engine and reports under the same
names. It splits commands the way a shell does (single and double quotes,
backslash escapes, `$( )`, backticks, comments), so `pkill -f 'x|guardclaw'`
is one command and `pgrep -l guardclaw; ./kill-switch.sh` is two. It reads a
`pkill`/`pgrep` (and `killall -r`) target as a regex: the target counts when
its match covers at least five characters of a guard name, so `guardcl.w`,
`x|guardclaw` and `uardclaw` count while `law.*`, `node.*claude` and
`guardrail` do not. With `-x` the whole name must match.

Covered: `systemctl stop|kill|disable|mask`, `service ... stop`,
`launchctl remove|bootout|unload|disable|kill|stop`, `rm`/`mv` of the guard's
launchd plist or systemd unit, `pkill`, `killall`, `kill $(pgrep ...)`,
`pgrep ... | xargs kill`, `VAR=$(pgrep ...); kill $VAR`, guard PID files,
`taskkill /IM` and `/FI`, `sc`/`sc.exe stop|delete|config`, `Stop-Service`,
`Set-Service -StartupType Disabled` and `Stop-Process`.

It also follows commands run through `sh|bash|zsh -c`, `su -c`, `eval`,
`watch`, `xargs`, `busybox`, `command`, `exec`, `time`, `nohup`, `env` and
`sudo`, and any `pkill`/`pgrep` target that spells a full guard name counts.

The first release's five self-protection regexes still run unchanged as a
backstop alongside the new patterns, so nothing that release detected is
dropped. That includes its known false positive: a guard name in a shell
comment after `pkill` (`pkill x # guardclaw note`) is still flagged.

Bounded work: more than 16 regex targets in one input, a target over 256
bytes, a target that does not compile, more than 16 nested substitutions
or nested shell scripts is treated as a match (fail closed).

These remain static text checks. They do not expand variables, aliases,
functions or scripts. A daemon that must survive a hostile agent needs
OS-level protection as well.

### CI

The DCO sign-off check is skipped for pull requests from organization owners
and members, including members whose org membership is private.

## Initial public source release

First public source release of the detection engine, CLI and corpus.
