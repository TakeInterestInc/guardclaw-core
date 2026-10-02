# GuardClaw for Claude Code (mod)

A deny-only guard that runs inside Claude Code as a mod: a plugin of function
hooks (Claude Code 2.1.287 and later, early access). It refuses dangerous tool
calls before anything beneath it can run or approve them, and it refuses to
load other mods that could approve tool calls.

```
 tool call from the model
        |
        v
 +------------------------------+   deny  ->  the model gets the reason as an error result
 | guardclaw (prependPlugins)   |-------->
 +------------------------------+
        | next(e): allowed
        v
 +------------------------------+
 | your other mods (user tier)  |   a mod here could approve a call; guardclaw
 +------------------------------+   refuses such mods at plugin.register
        |
        v
 settings hooks (PreToolUse), permission rules, the tool itself
```

## Why a mod as well as settings hooks

Settings hooks (`PreToolUse` and the rest) sit beneath every mod. The mods
documentation says a mod that approves tool calls can approve a call that one
of your own `PreToolUse` hooks blocked. A guard that lives only in settings
hooks, which is how the GuardClaw command hooks ship today, can be outvoted by
any mod you install. This mod sits above them.

## What it denies

Bash commands, matched after `$HOME` and `${HOME}` are spelled `~`:

| Class | Examples | Go rule it is ported from |
|---|---|---|
| Destructive | `rm -rf ~`, `rm -rf /`, `rm -r -f /*`, `mkfs`, `dd of=/dev/disk0`, fork bomb | `rm_rf_*`, `mkfs`, `dd_device`, `fork_bomb` |
| Pipe into a shell | `curl ... \| sh`, `wget -qO- ... \| sudo bash`, `bash <(curl ...)` | `curl_pipe_shell`, `pipe_shell` |
| Base64 decoded and run | `echo ... \| base64 -d \| sh`, `eval "$(... \| base64 --decode)"` | `pipe_base64_decode`, `eval_var` |
| Credential egress | `cat ~/.aws/credentials \| curl ...`, `curl -F f=@~/.ssh/id_ed25519 ...` | `curl_post_file`, `base64_curl`, `cat_credentials` |
| Backdoors and persistence | `>> ~/.ssh/authorized_keys`, `cp x ~/.ssh/...`, `nc -l ... -e`, `/dev/tcp/` | `ssh_key_append`, `nc_listen_exec`, `bash_socket` |
| Guard self-protection | `pkill guardclaw`, `launchctl unload ...guardclaw...`, editing this mod's folder | `guardclaw_*` |

`Write`, `Edit`, `MultiEdit` and `NotebookEdit` into `~/.ssh`, `~/.aws`,
`~/.gnupg`, cloud credential files, home-folder shell startup files,
`Library/LaunchAgents`, `/etc`, Claude Code's managed settings, or this mod's
own folder.

The rules come from `guardian/security/command_injection.go` and
`protected_paths.go` in this repo. Every deny reason names its rule, and where
a rule maps one to one onto a Go rule it keeps the Go name, so a block can be
traced to its source. Only the destructive,
pipe-to-shell, egress, backdoor and self-protection rules are ported. The Go
chaining, substitution and recon rules are left out, because a coding session
runs `$(...)`, `&& rm` and `; ls` constantly. Two Go rules are narrower here:
`rm -rf /tmp/build` and `rm -rf ./dist` pass (Go's `rm\s+-rf\s+/` and
`rm\s+-rf\s+\.` deny them), and `| shasum` passes (Go's `\|\s*sh` has no word
boundary).

## What it refuses to load

At `plugin.register`, a later user-tier mod whose scanned hooks reach
`tool.call`, `tool.check`, `session.append`, `classic.PreToolUse` or
`classic.PermissionRequest` (globs such as `tool.*` and `*` count) is refused,
and the reason is logged to the transcript. To load one you trust, add it to
the `allowMods` option, ideally as `name@marketplace`, since a bare name is
whatever that mod's own `plugin.json` says.

## Fail closed

- If a matcher throws, for example an `extraDenyPatterns` entry that is not a
  valid regular expression, every call it would have checked is denied with
  `matcher_error` in the reason.
- If the hook throws past its own guard or runs out of time, its `.catch`
  handler denies.
- If the `plugin.register` check fails, the mod is refused.

It never approves anything. Allowed calls go on with `next(e)` to whatever
would have decided them anyway.

## What it uses

`claude plugin validate` reports the whole surface: `$.clock.now`,
`$.state.get` / `$.state.set` (one value, today's deny count), `$.ui.log` and
`$.ui.status`. Network calls, process spawning, file reads and writes,
environment reads and secrets are all absent from that list.

## Install

Claude Code 2.1.287 or later, with mods turned on for your account.

From the marketplace in this repo:

```
/plugin marketplace add TakeInterestInc/guardclaw-core
/plugin install guardclaw@guardclaw
```

Or from a checkout, for one session:

```
claude --plugin-dir /path/to/guardclaw-core/claude-code-mod
```

Then seat it first. Add it to `prependPlugins` so it runs before, and judges,
every mod you install:

```json
{ "prependPlugins": ["guardclaw@guardclaw"] }
```

(`guardclaw@guardclaw` is the marketplace install. A `--plugin-dir` load is
keyed `guardclaw@inline`.)

In your own `~/.claude/settings.json` this works only on a machine with no
managed settings and outside a Team or Enterprise plan. Where either applies,
your administrator owns `prependPlugins` and lists it in managed settings. If
the built-in `sec-default@builtin` guard loads for you, list GuardClaw after it.
Without `prependPlugins` the mod still loads in the user tier, but where it
sits among your other mods, and so which of them it gets to judge, is not
something this mod controls.

Options (`/config`, or `pluginConfigs.guardclaw.options` in settings):

| Option | Default | Meaning |
|---|---|---|
| `allowMods` | `[]` | Mods allowed to load even though they hook tool approval |
| `extraDenyPatterns` | `[]` | Your own regular expressions, matched case-insensitively against every Bash command |

The status line under the prompt reads `GuardClaw: N blocked today` (UTC day,
counted per session).

## What it cannot do

- **Crash, safe mode and a failed load remove it.** If the module fails to
  load, or Claude Code runs with `--safe-mode` or hooks turned off, the guard is
  absent and nothing here denies anything. That is the case for keeping the
  GuardClaw settings hooks and the GuardClaw daemon running as well.
- **It matches patterns and does no sandboxing.** A command spelled to slip past the
  patterns (variables, aliases, a script that does the work, a symlink to a
  protected path) gets through. Paths are matched by spelling and never resolved.
- **It sees tool calls and nothing else a mod does.** A mod that runs programs
  itself through `$.process.run` never makes a tool call. It is refused only if
  it also hooks one of the events above.
- **Ordering inside the user tier is not ours.** Only `prependPlugins` puts it
  first.
- **The mods API is early access** and can change between Claude Code releases.

## How it relates to the GuardClaw daemon

This mod is a fast first line inside one Claude Code session. The GuardClaw
daemon is the long-lived guard on the machine, with the full rule set, policy,
audit trail and coverage beyond Claude Code. Run both. The mod does not call
the daemon in this version: it reaches no network and spawns no process.

## Develop

```
claude plugin validate claude-code-mod
claude plugin test claude-code-mod
```

The tests in `tests/guard.test.ts` run each deny and allow case through the
engine, load a real inline mod that tries to approve a call the guard denies,
and check that a throwing matcher denies.

## License

Apache-2.0, as the rest of this repository.
