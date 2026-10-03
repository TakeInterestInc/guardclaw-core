# GuardClaw for Claude Code (mod)

A deny-only guard that runs inside Claude Code as a mod: a plugin of function
hooks (Claude Code 2.1.287 and later, early access). Every shell command the
model asks to run is judged by the GuardClaw Go engine, credential and
settings files are kept away from the file tools, and other mods that could
approve tool calls are refused before they load.

```
 tool call from the model
        |
        v
 +-------------------------------+  shell command on stdin, no shell  +------------------------------+
 | guardclaw (prependPlugins)    |----------------------------------->| guardclaw-scan               |
 |  - file paths checked in JS   |<-----------------------------------|  --stdin-command --agent     |
 +-------------------------------+  exit 1 deny, 0 allow, else deny   +------------------------------+
        | next(e): allowed                  deny -> the model gets the reason as an error result
        v
 +-------------------------------+
 | your other mods (user tier)   |   a mod here could approve a call; guardclaw
 +-------------------------------+   refuses such mods at plugin.register
        |
        v
 settings hooks (PreToolUse), permission rules, the tool itself
```

## Threat model

It guards **model-initiated tool calls**: what the model asks Bash, Monitor,
the file tools or an MCP tool to do. It does not watch what another mod does
on its own. A mod that runs programs through `$.process.run`, writes files
through `$.fs.write` or reaches the network never makes a tool call, so it is
handled at admission instead: such a mod is refused before it loads (see
below).

Settings hooks (`PreToolUse` and the rest) sit beneath every mod, and a mod
that approves tool calls can approve a call one of your `PreToolUse` hooks
blocked. A guard that lives only in settings hooks can be outvoted by any mod
you install. This mod sits above them when it is seated in `prependPlugins`.

## Shell commands: the Go engine decides

For `Bash`, `Monitor`, any tool whose input has a string `command`, and an MCP
tool's `command`, `cmd`, `script` or `code` argument, the mod runs

```
guardclaw-scan --stdin-command --agent
```

through `$.process.run` with the command on standard input and no shell in
between. The scanner runs `CheckAgentCommand` from
`guardian/security/agent_command.go` on the command as written and again after
`NormalizeInput` (NFKC, homoglyph and zero-width folding), and prints one JSON
line.

| Scanner result | What the mod does |
|---|---|
| exit 1 | denies, naming the engine's rule (`rm_rf_home`, `pipe_shell_wrapped`, ...) |
| exit 0 with `{"decision":"allow"}` | passes the call on with `next(e)` |
| exit 2, any other exit, unparseable output, a crash or a 10 s timeout | denies **that call only** (`scanner_error`); the next call is scanned again |

The mod runtime has no WebAssembly by design ("a module that needs compiled
code runs it in a process of its own through `$.process.run`"), which is why
the engine runs as a process rather than inside the mod.

A JavaScript backstop (`hooks/rules.ts`, a partial hand-port of the Go rules)
runs first and can only add denies. Your `extraDenyPatterns` run there too.

### Agent mode

Without `--agent` the scanner is strict (`CheckCommandInjection`): chaining
(`&&`, `;`, `|`, `&`) and substitution (`$( )`, backticks) deny on their own,
so `cd src && npm test` and `echo $(date)` are blocked. That stays the default
for untrusted input. `--agent` keeps every other rule and looks inside
instead:

- The whole line is matched against every pattern in a deny category
  (destructive, pipe into a shell or interpreter, data exfiltration), every
  non-structural pattern at full severity, and the self-protection check. A
  download inside a substitution (`$(curl ...)`) still denies.
- The line is then split the way a shell splits it (the self-protection
  parser), wrappers are opened (`sh -c`, `bash -c`, `eval`, `su -c`,
  `watch`, `xargs`, `find -exec`, `sudo`, `env`, `nice`, `$( )`, backticks,
  subshells, `if`/`then`) and every simple command inside is judged on its
  own, quotes resolved.
- `rm_rf_dot` is replaced by a precise check: a recursive `rm` of `.`, `./`,
  `..`, `*`, `~`, `/`, a home folder or a folder at its top, or a home dot
  folder denies; `./build` and `dist/` do not. `rm_rf_root` and `rm_rf_home`
  are unchanged, so `rm -rf /tmp/x` is still denied.
- `xargs` into a shell or interpreter denies (`ls | xargs bash`); `xargs wc
  -l` does not. `find` with `-delete` or an exec'd `rm` over `/`, `~` or a
  system folder denies, and so does `.` with no `-name`/`-path` filter.

Allowed in agent mode, measured: `cd src && npm test`, `go test ./... 2>&1 |
tail`, `echo $(date)`, `rm -rf ./build`, `make && make test`, `ls | grep x`,
`npm ci && npm test`, `git ls-files | xargs wc -l`, `npm test | tee test.log`.
Denied: the whole review corpus, plus a download piped to a shell after a
`cd`, and a credential file sent to the network from inside `$( )`.

### Install the scanner

```
go install github.com/TakeInterestInc/guardclaw-core/cmd/guardclaw-scan@latest
```

Then set the `scannerPath` option to the absolute path of the binary (for
example `~/go/bin/guardclaw-scan` spelled out in full). The default,
`guardclaw-scan`, is looked up on `PATH`, and anything that can change `PATH`
can change which program judges your commands.

### Degraded mode: when the scanner is missing

At `session.start` (and again after a hot reload) the mod probes the scanner
once by asking it to judge `rm -rf /`. If it cannot be started, or it does not
deny the probe, the session runs **degraded** and the status line says so with
the install line:

```
GuardClaw: 0 blocked today · scanner missing, only simple shell commands run. Install: go install github.com/TakeInterestInc/guardclaw-core/cmd/guardclaw-scan@latest
```

In degraded mode every shell command holding a wrapper or metacharacter is
denied outright: `;` `|` `&` a newline, a backtick, `$(`, `(`, `)`, `${`,
`<(` and `>(`, `eval`, `exec`, `source`, `sudo`, `doas`, `su`, `xargs`,
`sh -c` / `bash -c` / `zsh -c`, an interpreter given code with `-c` or `-e`,
`find` with `-exec` or `-delete`, and a command led by a wrapper such as
`nice`, `nohup`, `env`, `timeout` or `.`. A single plain command is checked
by the JavaScript rules. A scanner timeout in normal mode denies that call
and never switches the session to degraded.

## Files: checked in JavaScript, both modes

`Write`, `Edit`, `MultiEdit` and `NotebookEdit` are denied when the path,
after `~`, `$HOME` and `${HOME}` are expanded, or the place it really lands
(`$.fs.stat(path, { resolve: true }).realPath`, or its folder's for a new
file), is:

- `~/.ssh`, `~/.aws`, `~/.gnupg`, cloud and git credential files, home shell
  startup and package-auth files, `Library/LaunchAgents` and `LaunchDaemons`,
  `/etc`;
- `~/.claude/settings.json`, `~/.claude/settings.local.json` and any project
  `.claude/settings*.json` (hooks, permissions and enabled mods live there),
  `.mcp.json`, and Claude Code's managed settings;
- this mod's own folder, as loaded and as resolved.

Matching ignores case, since the default macOS volume does. A symbolic link
is judged by where it lands; a hard link or a case alias keeps its own
spelling, so this is a deny-list and best effort, as the API notes.

## What it refuses to load

At `plugin.register`, a later **user-tier or append-tier** mod is refused when
its scanned `uses` show any of:

- events `tool.call`, `tool.check`, `session.append`, `classic.PreToolUse`,
  `classic.PermissionRequest`, `config.set` (it could approve a call, rewrite
  a stored row or change settings), or `process.run`, `process.spawn`,
  `fs.stat`, `env.get` (it could answer the guard's own calls, for example
  hand the scanner call a clean verdict); globs such as `tool.*` and `*` count;
- calls `process.run`, `process.spawn`, `fs.write`, `config.set`,
  `tool.call`, `http.fetch` or `env.set`, or any `$.env.set` write (it could
  run programs, write files, change settings, act as the model or repoint
  `PATH`).

Two ways through, both read from the mod's provenance:

- **Trusted marketplaces** (`trustedMarketplaces`, default `builtin` and
  `claude-plugins-official`, Anthropic's own marketplace): any mod from one
  of them loads. Remove an entry to hold that marketplace to the same rule.
- **`allowMods`**: an exact `name@marketplace` id.

`inline` (a `--plugin-dir` folder, which names itself) is never trusted and a
bare name never matches. Everything else with risky uses is refused, and the
reason is logged to the transcript. Whether Claude Code stops a third-party
marketplace from calling itself `claude-plugins-official` has not been
verified here.

## Fail closed, deny only

- A matcher that throws (an `extraDenyPatterns` entry that does not compile,
  a `Bash` call whose `command` is not a string) denies with `matcher_error`.
- A hook that throws past its own guard or runs out of time is denied by its
  `.catch` handler.
- A `plugin.register` check that fails refuses the mod.
- It never returns an allow or an approval. Allowed calls go on with
  `next(e)` to whatever would have decided them anyway.

## What it uses

`claude plugin validate claude-code-mod` reports the surface: `$.process.run`
(the scanner, by argv, no shell), `$.fs.stat` (where a written path lands),
`$.env.get("HOME")`, `$.clock.now`, `$.state.get` / `$.state.set` (one
value, today's deny count), `$.ui.log` and `$.ui.status`. No network, no file
writes, no environment writes.

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

**`prependPlugins` is required** for the guard to run before, and judge,
every mod you install:

```json
{ "prependPlugins": ["guardclaw@guardclaw"] }
```

(`guardclaw@guardclaw` is the marketplace install. A `--plugin-dir` load is
keyed `guardclaw@inline`.) Without it the mod loads in the user tier, and
where it sits among your other mods, so which of them it judges, is not
something it controls.

In your own `~/.claude/settings.json` this works only on a machine with no
managed settings and outside a Team or Enterprise plan. Where either applies,
your administrator owns `prependPlugins` and lists it in managed settings. If
the built-in `sec-default@builtin` guard loads for you, list GuardClaw after
it.

**Managed-tier caveat.** In Claude Code 2.1.287 a plugin that managed
settings enable but that is loaded from a copy (rather than the managed
install) may still run in the user tier. Check where it sits before relying
on it: a refusal logged by GuardClaw for a mod you know is earlier in the
chain is the sign it is not first.

Options (`/config`, or `pluginConfigs.guardclaw.options` in settings):

| Option | Default | Meaning |
|---|---|---|
| `scannerPath` | `guardclaw-scan` | The scanner binary; use an absolute path |
| `trustedMarketplaces` | `["builtin", "claude-plugins-official"]` | Marketplaces whose mods load despite the admission rules |
| `allowMods` | `[]` | Exact `name@marketplace` ids allowed to load despite the admission rules |
| `extraDenyPatterns` | `[]` | Your own regular expressions, matched case-insensitively against every shell command before the scanner runs |

The status line reads `GuardClaw: N blocked today` (UTC day), with the
degraded notice appended when the scanner is missing.

## What it cannot do

- **A crash, `--safe-mode` or a failed load unloads it.** If the module fails
  to load, or Claude Code runs with `--safe-mode` or hooks turned off, the
  guard is absent and nothing here denies anything. Keep the GuardClaw
  settings hooks and the daemon running as well.
- **It matches patterns and does no sandboxing.** A command spelled to slip
  past the engine's patterns (a script that does the work, variables, aliases)
  can get through, and the engine's verdict is only as good as its rules.
  Agent mode in particular allows a download followed by a separate run
  (`curl -o x.sh ... && bash x.sh`): each half is ordinary on its own.
- **Ordering inside the user tier is not its own.** Only `prependPlugins`
  puts it first.
- **The mods API is early access** and can change between releases.

## Develop

```
go test -race ./...                       # includes the scanner corpus and fixture check
claude plugin validate claude-code-mod
claude plugin test claude-code-mod
```

The mod test kit runs no host processes (a test answers `process.run`
itself), so `tests/scanner-fixture.ts` holds what `guardclaw-scan
--stdin-command --agent`, built from this repo, answers for every command the
tests send. The Go test `TestModScannerFixture` fails whenever the scanner and the
fixture disagree; regenerate with

```
go test ./cmd/guardclaw-scan -run TestModScannerFixture -update
```

`tests/guard.test.ts` runs the shared corpus (`MUST_DENY`, `MUST_ALLOW`)
through the mod with the scanner present and again with it missing, and
covers scanner failures, Monitor and MCP arguments, file paths and symbolic
links, and admission with real inline mods.

## License

Apache-2.0, as the rest of this repository.
