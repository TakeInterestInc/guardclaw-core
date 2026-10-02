// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0
//
// GuardClaw deny rules for the Claude Code mod. Pure functions: no `$`, no
// I/O, so they run the same inside a hook and inside a test.
//
// Ported from guardian/security/command_injection.go (rule names kept, so a
// deny here can be traced to its Go twin) and guardian/security/
// protected_paths.go. Only the destructive, pipe-to-shell, secret-egress,
// backdoor and self-protection rules are ported. The chaining, substitution
// and recon rules are left out on purpose: a coding agent runs `$(...)`,
// `&& rm` and `; ls` all day, and a deny-only mod that blocks ordinary work
// gets uninstalled. Where a Go rule was broader than a coding session can
// live with (`rm -rf ./build`, `| shasum`), the port is narrower and says so.

export type Verdict = { rule: string; reason: string }

const SHELLS = String.raw`(?:sudo\s+)?(?:env\s+(?:\S+=\S*\s+)*)?(?:ba|z|k|c|tc|da|fi)?sh\b`
const INTERPRETERS = String.raw`(?:sudo\s+)?(?:python[0-9.]*|perl|ruby|node|php|osascript)\b`
const FETCHERS = String.raw`\b(?:curl|wget|fetch)\b`

// Paths whose contents are credentials (DefaultSystemProtectedPaths, user-home
// and system identity entries). Matched against a command after `$HOME` and
// `${HOME}` are spelled `~`.
const SECRET_PATH = String.raw`(?:\.ssh/|\.aws/(?:credentials|config)|\.gnupg/|\.netrc\b|\.git-credentials\b|\.config/git/credentials|\.npmrc\b|\.pypirc\b|\.docker/config\.json|\.kube/config|\.config/gcloud/|\.gcloud/|\.azure/|\.anthropic/|\.claude/credentials|\.terraform\.d/credentials|\.cargo/credentials|\.gem/credentials|/etc/(?:passwd|shadow|gshadow|sudoers)|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|(?:^|[\s/'"=@])\.env(?:\.[\w-]+)?\b|Library/Keychains/)`
const SENDERS = String.raw`(?:\b(?:curl|wget|nc|ncat|netcat|socat|telnet|ftp|sftp|scp|rsync|mail|mailx|sendmail)\b|/dev/(?:tcp|udp)/)`
const READERS = String.raw`\b(?:cat|base64|tar|zip|gzip|xxd|od|openssl|head|tail|strings|less|more|cp|gpg)\b`

type Rule = { name: string; re: RegExp; reason: string }

// Patterns tested against the whole command after normalize().
const COMMAND_RULES: readonly Rule[] = [
  // Destructive (CmdCategoryDestructive). rm targets are handled by rmVerdict.
  { name: 'rm_no_preserve', re: /\brm\b[^;&|\n]*--no-preserve-root/i, reason: 'rm --no-preserve-root' },
  { name: 'brace_rm_rf', re: /\{\s*rm\s*,\s*-[rf]+\s*,/, reason: 'brace-expanded rm -rf' },
  { name: 'ifs_rm', re: /\brm\$\{?IFS/i, reason: 'rm with $IFS word splitting' },
  { name: 'mkfs', re: /\bmkfs(?:\.\w+)?\s+/i, reason: 'formats a filesystem' },
  { name: 'dd_device', re: /\bdd\b[^;&|\n]*\bof=\/dev\/(?!null\b|stdout\b|stderr\b)/i, reason: 'dd writing to a device' },
  { name: 'redirect_sda', re: />\s*\/dev\/(?:sd[a-z]|disk\d|nvme\d|hd[a-z])/i, reason: 'writes over a disk device' },
  { name: 'fork_bomb', re: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;/, reason: 'fork bomb' },
  { name: 'chmod_777_root', re: /\bchmod\s+(?:-R\s+)?0?777\s+\/(?:\s|$)/i, reason: 'chmod 777 on /' },
  { name: 'chown_root', re: /\bchown\s+-R\s+\S+\s+\/(?:\s|$)/i, reason: 'recursive chown of /' },
  { name: 'shred', re: /\bshred\s+/i, reason: 'shred destroys file contents' },
  // Guard self-protection (guardclaw_* rules).
  { name: 'guardclaw_service_stop', re: /\b(?:systemctl|service)\s+(?:stop|disable|mask)\s+(?:guardclaw|guardian)(?:\.service)?\b/i, reason: 'stops the GuardClaw service' },
  { name: 'guardclaw_launchctl_disable', re: /\blaunchctl\s+(?:unload|disable|bootout)\s+.*(?:guardclaw|guardian)/i, reason: 'unloads the GuardClaw agent' },
  { name: 'guardclaw_process_kill', re: /\b(?:killall|pkill)\s+.*(?:guardclaw|guardian)\b/i, reason: 'kills GuardClaw' },
  { name: 'guardclaw_taskkill', re: /\btaskkill\s+\/IM\s+(?:guardclaw|guardian)(?:\.exe)?\b/i, reason: 'kills GuardClaw' },
  { name: 'guardclaw_sc_stop', re: /\bsc\s+stop\s+(?:guardclaw|guardian)\b/i, reason: 'stops the GuardClaw service' },
  // Pipe into a shell (CmdCategoryPipe). Go's `\|\s*(sh|bash)` has no word
  // boundary and so also matched `| shasum`; this one ends at a boundary.
  { name: 'curl_pipe_shell', re: new RegExp(`${FETCHERS}[^;\\n]*\\|\\s*${SHELLS}`, 'i'), reason: 'downloads a script and pipes it into a shell' },
  { name: 'curl_pipe_interpreter', re: new RegExp(`${FETCHERS}[^;\\n]*\\|\\s*${INTERPRETERS}`, 'i'), reason: 'downloads code and pipes it into an interpreter' },
  { name: 'pipe_shell', re: new RegExp(`\\|\\s*${SHELLS}(?!\\s*-n\\b)`, 'i'), reason: 'pipes text into a shell' },
  { name: 'shell_process_subst_fetch', re: new RegExp(`\\b(?:ba|z|k|da)?sh\\s+<\\(\\s*${FETCHERS}|\\bsource\\s+<\\(\\s*${FETCHERS}|\\.\\s+<\\(\\s*${FETCHERS}`, 'i'), reason: 'runs a downloaded script through process substitution' },
  { name: 'shell_c_fetch', re: new RegExp(`\\b(?:ba|z|k|da)?sh\\s+-c\\s+["']?\\$\\(\\s*${FETCHERS}`, 'i'), reason: 'runs a downloaded script through sh -c' },
  { name: 'eval_fetch', re: new RegExp(`\\beval\\b[^;\\n]*\\$\\(\\s*${FETCHERS}`, 'i'), reason: 'evals a download' },
  // Base64-decoded execution (pipe_base64_decode, eval_var).
  { name: 'base64_decode_exec', re: new RegExp(`\\bbase64\\s+(?:-[a-zA-Z]*[dD][a-zA-Z]*|--decode)\\b[^;\\n]*\\|\\s*(?:${SHELLS}|${INTERPRETERS})`, 'i'), reason: 'decodes base64 and runs it' },
  { name: 'eval_base64', re: /\b(?:eval|exec)\b[^;\n]*\bbase64\s+(?:-[a-zA-Z]*[dD][a-zA-Z]*|--decode)\b/i, reason: 'evals base64-decoded text' },
  { name: 'shell_c_base64', re: /\b(?:ba|z|k|da)?sh\s+-c\s+["']?[^;\n]*\bbase64\s+(?:-[a-zA-Z]*[dD][a-zA-Z]*|--decode)\b/i, reason: 'runs base64-decoded text through sh -c' },
  { name: 'powershell_enc', re: /\bpowershell(?:\.exe)?\s+-(?:e|ec|enc|encodedcommand)\b/i, reason: 'runs an encoded PowerShell command' },
  // Secret egress (CmdCategoryExfil), narrowed to a credential path being
  // the data that leaves, so `ssh -i ~/.ssh/key host` is not caught.
  { name: 'secret_pipe_sender', re: new RegExp(`${READERS}[^|;\\n]*${SECRET_PATH}[^;\\n]*\\|[^;\\n]*${SENDERS}`, 'i'), reason: 'reads a credential file and pipes it to the network' },
  { name: 'secret_redirect_sender', re: new RegExp(`${SENDERS}[^;\\n]*<\\s*\\S*${SECRET_PATH}`, 'i'), reason: 'feeds a credential file into a network command' },
  { name: 'curl_post_file', re: new RegExp(`\\b(?:curl|wget)\\b[^;\\n]*(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file|--post-file)[=\\s]*["']?[^"'\\s]*@?\\S*${SECRET_PATH}`, 'i'), reason: 'uploads a credential file' },
  { name: 'subst_secret_sender', re: new RegExp(`${SENDERS}[^;\\n]*\\$\\([^)]*${SECRET_PATH}`, 'i'), reason: 'sends a credential file inside a command substitution' },
  { name: 'dev_tcp', re: /\/dev\/(?:tcp|udp)\//, reason: 'opens a raw network socket from the shell' },
  // Backdoors (CmdCategoryBackdoor).
  { name: 'nc_listen_exec', re: /\bnc\s+-l.*-e\b/i, reason: 'netcat listener that runs a shell' },
  { name: 'socat_exec', re: /\bsocat\s+.*EXEC/i, reason: 'socat bound to a program' },
  { name: 'msfvenom', re: /\bmsfvenom\b/i, reason: 'payload generator' },
]

// Home-relative paths a session has no business writing: credentials and the
// shell startup files a backdoor appends to.
const PROTECTED_WRITE: readonly Rule[] = [
  { name: 'write_ssh', re: /(?:^|\/)\.ssh(?:\/|$)/, reason: 'writes into ~/.ssh' },
  { name: 'write_aws', re: /(?:^|\/)\.aws\//, reason: 'writes AWS credentials' },
  { name: 'write_gnupg', re: /(?:^|\/)\.gnupg\//, reason: 'writes into ~/.gnupg' },
  { name: 'write_cloud_creds', re: /(?:^|\/)(?:\.kube\/config|\.docker\/config\.json|\.config\/gcloud\/|\.azure\/|\.git-credentials$|\.netrc$|\.config\/git\/credentials$)/, reason: 'writes a credential file' },
  { name: 'write_home_rc', re: /^(?:~|\/Users\/[^/]+|\/home\/[^/]+|\/root)\/\.(?:bashrc|bash_profile|bash_login|profile|zshrc|zprofile|zshenv|zlogin|npmrc|pypirc)$/, reason: 'writes a shell startup or package-auth file in your home folder' },
  { name: 'write_launch_agent', re: /(?:^|\/)Library\/Launch(?:Agents|Daemons)\//, reason: 'installs a launch agent' },
  { name: 'write_etc', re: /^\/etc\//, reason: 'writes under /etc' },
  { name: 'write_managed_settings', re: /(?:\/Library\/Application Support\/ClaudeCode\/|^\/etc\/claude-code\/)managed-settings/, reason: 'edits the managed settings that seat this guard' },
]

const SYSTEM_DIRS = /^\/(?:bin|boot|dev|etc|home|lib|lib64|opt|private|proc|root|sbin|sys|usr|var|Applications|Library|System|Users|Volumes)\/?$/
const HOME_DIR = /^\/(?:Users|home)\/[^/]+\/?$/

/** Spells `$HOME`, `${HOME}` and `"$HOME"` as `~` and drops backslash escapes, so one pattern covers each. */
export function normalize(command: string): string {
  return command
    .replace(/["']?\$\{?HOME\}?["']?/g, '~')
    .replace(/\\(?=[A-Za-z~\/.-])/g, '')
}

function unquote(word: string): string {
  return word.replace(/^["']|["']$/g, '')
}

/** Splits a command line into simple commands at ; && || | & and newlines. Best effort, not a shell parser. */
export function segments(command: string): string[] {
  return command.split(/\|\||&&|[;|&\n]/).map(s => s.trim()).filter(Boolean)
}

function words(segment: string): string[] {
  const out = segment.split(/\s+/).map(unquote).filter(Boolean)
  // Drop wrappers that do not change what runs.
  while (out.length > 0) {
    const head = out[0] ?? ''
    if (/^(?:sudo|command|exec|nohup|time|nice|doas)$/.test(head) || /^\w+=/.test(head)) out.shift()
    else if (head === 'env') out.shift()
    else break
  }
  return out
}

function isDangerousRmTarget(target: string): boolean {
  const t = target.replace(/\/+$/, '') || '/'
  if (t === '/' || t === '/*' || t === '/.' || t === '/..') return true
  if (/^~(?:\/\*?|\/\.)?$/.test(target) || t === '~') return true
  if (t === '.' || t === '..' || t === '*' || t === './*' || t === '../*' || t === '.*') return true
  if (SYSTEM_DIRS.test(target) || SYSTEM_DIRS.test(t)) return true
  if (HOME_DIR.test(target)) return true
  return false
}

/**
 * rm_rf_root, rm_rf_home, rm_rf_glob and rm_rf_dot, narrowed: Go's
 * `rm\s+-rf\s+/` also matched `rm -rf /tmp/build`; this denies a recursive rm
 * only when a target is the root, a home folder, a top-level system folder,
 * `.`, `..` or a bare glob.
 */
export function rmVerdict(command: string): Verdict | undefined {
  for (const segment of segments(command)) {
    const w = words(segment)
    const head = w[0] ?? ''
    if (!/(?:^|\/)rm$/.test(head)) continue
    let recursive = false
    const targets: string[] = []
    let endOfFlags = false
    for (const word of w.slice(1)) {
      if (!endOfFlags && word === '--') { endOfFlags = true; continue }
      if (!endOfFlags && /^--recursive$/.test(word)) { recursive = true; continue }
      if (!endOfFlags && /^-[a-zA-Z]+$/.test(word)) { if (/[rR]/.test(word)) recursive = true; continue }
      if (!endOfFlags && word.startsWith('--')) continue
      targets.push(word)
    }
    if (!recursive) continue
    const hit = targets.find(isDangerousRmTarget)
    if (hit !== undefined) {
      const rule = hit.startsWith('~') || HOME_DIR.test(hit) ? 'rm_rf_home' : hit.startsWith('/') ? 'rm_rf_root' : hit.includes('*') ? 'rm_rf_glob' : 'rm_rf_dot'
      return { rule, reason: `recursive rm of ${hit}` }
    }
  }
  return undefined
}

/** The places a shell command writes: redirect targets, tee arguments, and the last argument of cp, mv, install and ln. */
export function writeTargets(command: string): string[] {
  const out: string[] = []
  for (const m of command.matchAll(/(?:\d?>>?|>\|)\s*([^\s;|&<>]+)/g)) {
    if (m[1] !== undefined) out.push(unquote(m[1]))
  }
  for (const segment of segments(command)) {
    const w = words(segment)
    const head = (w[0] ?? '').replace(/^.*\//, '')
    const args = w.slice(1).filter(a => !a.startsWith('-'))
    if (head === 'tee') out.push(...args)
    if (['cp', 'mv', 'install', 'ln', 'rsync'].includes(head) && args.length >= 2) out.push(args[args.length - 1] ?? '')
    if (head === 'sed' && w.some(a => /^-[a-zA-Z]*i/.test(a) || a.startsWith('--in-place'))) out.push(...args.slice(1))
  }
  return out.filter(Boolean)
}

/** The write rule a path breaks, if any. `~`, `$HOME` and `${HOME}` count as the home folder. */
export function protectedWrite(path: string, guardRoot?: string): Verdict | undefined {
  const p = normalize(path)
  if (guardRoot && guardRoot.length > 1) {
    const root = guardRoot.replace(/\/+$/, '')
    if (p === root || p.startsWith(`${root}/`)) return { rule: 'write_guard_itself', reason: `edits the GuardClaw mod itself (${root})` }
  }
  for (const rule of PROTECTED_WRITE) {
    if (rule.re.test(p)) return { rule: rule.name, reason: `${rule.reason}: ${path}` }
  }
  return undefined
}

/**
 * The first rule a Bash command breaks, or undefined when it may run.
 * `extra` holds the person's own patterns (userConfig `extraDenyPatterns`);
 * an invalid one throws, and the caller turns the throw into a deny.
 */
export function checkCommand(command: unknown, guardRoot?: string, extra: readonly string[] = []): Verdict | undefined {
  if (typeof command !== 'string') throw new TypeError(`Bash command is ${typeof command}, not a string`)
  const c = normalize(command)
  for (const source of extra) {
    const re = new RegExp(source, 'i')
    if (re.test(c)) return { rule: 'user_pattern', reason: `matches your extraDenyPatterns entry /${source}/` }
  }
  const rm = rmVerdict(c)
  if (rm) return rm
  for (const rule of COMMAND_RULES) {
    if (rule.re.test(c)) return { rule: rule.name, reason: rule.reason }
  }
  for (const target of writeTargets(c)) {
    const v = protectedWrite(target, guardRoot)
    if (v) return v
  }
  if (guardRoot && guardRoot.length > 1 && c.includes(guardRoot) && /\b(?:rm|mv|cp|sed|perl|tee|truncate|ln|chmod|unlink)\b|>/.test(c)) {
    return { rule: 'write_guard_itself', reason: `changes the GuardClaw mod itself (${guardRoot})` }
  }
  return undefined
}

/** File tools and the input field that names the file each one writes. */
export const WRITE_TOOLS: Readonly<Record<string, string>> = {
  Write: 'file_path',
  Edit: 'file_path',
  MultiEdit: 'file_path',
  NotebookEdit: 'notebook_path',
}

/** Events through which a mod can approve a tool call or rewrite a stored row. */
export const RISKY_EVENTS: readonly string[] = ['tool.call', 'tool.check', 'session.append', 'classic.PreToolUse', 'classic.PermissionRequest']

/** Whether a registration pattern as written (`*`, `tool.*`, `!tool.describe`) covers the event. */
export function coversEvent(pattern: string, event: string): boolean {
  if (pattern.startsWith('!')) return pattern.slice(1) !== event
  if (pattern === '*') return true
  if (pattern.endsWith('.*')) return event.startsWith(pattern.slice(0, -1))
  return pattern === event
}

/** The risky events a mod's scanned `uses.events` reach. */
export function riskyEventsOf(events: readonly string[]): string[] {
  return RISKY_EVENTS.filter(ev => events.some(p => coversEvent(p, ev)))
}
