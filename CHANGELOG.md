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

### Self-protection command patterns

Pattern names are unchanged; the patterns are wider. They now catch flags
before the unit name, `launchctl remove|bootout|unload|kill|stop`,
`systemctl stop|kill|disable|mask`, `rm`/`mv` of the guard's launchd plist or
systemd unit, kill by a PID from `pgrep`/`pidof` in the same command,
`taskkill /IM` and `/FI` with globs, `sc`/`sc.exe stop|delete|config`,
`Stop-Service`, `Stop-Process`, shell quoting or escapes inside the name, and
regex or wildcard `pkill`/`killall`/`pgrep` targets. A match stays inside one
command: a separator, pipe or `#` comment ends it. These remain text checks; a
daemon that must survive a hostile agent needs OS-level protection as well.

### CI

The DCO sign-off check is skipped for pull requests from organization owners
and members, including members whose org membership is private.

## Initial public source release

First public source release of the detection engine, CLI and corpus.
