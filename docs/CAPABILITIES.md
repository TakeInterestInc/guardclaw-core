# Supported boundaries and gaps

First public draft, checked against official documentation on 2026-10-03. Host
versions, account access and managed policy differ. Synthetic adapter tests are
not a live integration certification. A README or AGENTS.md cannot override
platform permissions or protect actions outside a real mediated tool boundary.

| Host / path | Interception and configuration | Logging in this repo | Status |
|---|---|---|---|
| Claude Code classic command hooks, macOS/Linux | PreToolUse receives tool name/arguments; adapter can return deny or ask. Allow emits no host approval. Setup produces a preview only. | Chained decision receipts and observed PostToolUse/PostToolUseFailure receipts; arguments/results omitted. | New bounded adapter, synthetic tests; requires host enrollment/verification. |
| Claude Code mod (`claude-code-mod/`) | Existing tool.call guard scans selected shell fields, file-tool writes and later mod admission; depends on version/placement. | Existing deny count and transcript messages only. | Legacy adapter; no personal policy or chained receipts. |
| Local Codex | Host hooks cover supported Bash, apply_patch, MCP and local function paths. Native MCP/app per-tool approval settings can prompt. | Native host logs; this repo has no validated Codex receipt adapter. | Setup guidance only; do not install the Claude adapter. |
| Cloud Work / dots | Enterprise admin-managed remote MCP hooks can cover supported orchestrator events; local configuration/plugin/command hooks are unsupported even with local execution. | No repo adapter or complete audit trail here. | Requires an admin integration; a checkout cannot install it. |
| Cowork | Native connector permission controls can require approval in Manual mode. | Host activity; no GuardClaw receipts here. | Guidance only; no verified global interception adapter. |
| Custom runtime embedding Go | Caller must route actual actions through checks and enforce decisions. | Caller can use receipt library with its own durable boundary. | Library primitives, not a ready-made email/MCP proxy. |

## Claude Code

The [official hook reference](https://code.claude.com/docs/en/hooks) documents
PreToolUse deny/ask, exact MCP tool names, post-tool success/failure observations,
managed hook restrictions, and nonblocking command-hook timeouts. The
[mod events reference](https://code.claude.com/docs/en/plugins/mods/events) covers
function hooks separately. The new command-hook adapter does not install or
control mods. Tool-approving mods, another hook rewriting arguments, disabled or
unavailable hooks, unmanaged processes and direct filesystem/network calls can
change coverage. A pattern no-match is not a safety proof. Native permission
rules and OS sandboxing remain necessary. Shell review covers the invocation,
not every subsequent program effect. See SETUP.md for explicit opt-in.

## Codex: use the host's actual permission boundary

[Codex hooks](https://learn.chatgpt.com/docs/hooks) explicitly state that
PreToolUse `ask` is parsed but unsupported: a failed hook can continue the tool.
Do not translate ask to allow or advertise it as an email gate. Supported denial
can block supported local tools, but this repo does not ship a Codex adapter.

For an already-installed MCP server, a **candidate** native setting can use:

```toml
[mcp_servers.YOUR_SERVER.tools.YOUR_SEND_TOOL]
approval_mode = "prompt"
```

Use actual names from your configuration and verify the installed version. This
is a native host approval setting, not GuardClaw interception or receipt logging.
For apps, inspect the actual app/tool approval controls instead of assuming MCP
settings also govern connectors. Do not apply this example as a blanket overwrite
or enable a new server. See the [official MCP guide](https://developers.openai.com/codex/mcp/)
and [configuration reference](https://developers.openai.com/codex/config-reference/).

## Cloud dots / Work

The [official managed hook section](https://learn.chatgpt.com/docs/hooks#managed-hooks-from-requirementstoml)
requires supported enterprise configuration and remote MCP callbacks. A local Go
binary, prompt or plugin is not that integration. Managed hook callback failures
may not block actions. Use existing native action approvals; any future adapter
needs separate design, event/failure tests and admin authorization. No hosted
service, credentials or cloud installer are included here.

## Cowork

The [official Cowork guide](https://support.claude.com/en/articles/13345190-get-started-with-claude-cowork)
describes Manual mode plus connector tools marked Needs approval. For an
already-connected email tool, use that native configuration and confirm the send
operation prompts. Auto may approve an action without a person, and Skip is not
an ask-before-send workflow. Instructions can explain your policy but are not
GuardClaw enforcement. A local Claude Code plugin should not be assumed to run
across Cowork's cloud/browser/connector paths.
