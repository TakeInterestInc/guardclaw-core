// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0
//
// GuardClaw as a Claude Code mod: deny-only, fail-closed. It never approves a
// call, never runs a process, never reaches the network and never writes a
// file. What it uses on `$`: plugin (its own name and folder), state (the
// day's deny count), clock (to know the day), ui.status and ui.log.

import type { EngineInterface, Register } from 'claude-code'
import { checkCommand, protectedWrite, riskyEventsOf, WRITE_TOOLS, type Verdict } from './rules.ts'

function list(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string' && v.trim() !== '').map(v => v.trim())
  if (typeof value === 'string' && value.trim() !== '') return value.split(',').map(v => v.trim()).filter(Boolean)
  return []
}

async function today($: EngineInterface): Promise<string> {
  return new Date(await $.clock.now()).toISOString().slice(0, 10)
}

async function showCount($: EngineInterface, count: number): Promise<void> {
  $.ui.status(`GuardClaw: ${count} blocked today`)
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
        await showCount($, count)
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

export const register: Register = (on, options) => {
  const allowMods = list(options.allowMods)
  const extraDenyPatterns = list(options.extraDenyPatterns)

  on('session.start', async ($, e, next) => {
    const result = await next(e)
    try {
      const day = await today($)
      const { value } = await $.state.get({ plugin: 'guardclaw', key: 'blocked' })
      await showCount($, value && value.day === day ? value.count : 0)
    } catch {
      // A status line that fails to draw changes nothing about what is denied.
    }
    return result
  })

  on('tool.call', async ($, e, next) => {
    let verdict: Verdict | undefined
    try {
      if (e.tool === 'Bash') {
        verdict = checkCommand(e.command, $.plugin.root, extraDenyPatterns)
      } else if (e.tool in WRITE_TOOLS) {
        const field = WRITE_TOOLS[e.tool] ?? 'file_path'
        const path = (e as unknown as Record<string, unknown>)[field]
        if (typeof path !== 'string') throw new TypeError(`${e.tool} ${field} is ${typeof path}, not a string`)
        verdict = protectedWrite(path, $.plugin.root)
      }
    } catch (error) {
      // Fail closed: a matcher that cannot decide denies.
      const message = error instanceof Error ? error.message : String(error)
      verdict = { rule: 'matcher_error', reason: `the GuardClaw matcher failed (${message}), so the call is denied rather than let through` }
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

  on('plugin.register', { tier: 'user' }, ($, e, next) => {
    if (e.root === $.plugin.root) return next(e)
    const risky = riskyEventsOf(e.uses.events)
    if (risky.length === 0) return next(e)
    if (allowMods.includes(e.name) || allowMods.includes(e.provenance)) {
      log($, `GuardClaw: allowed mod ${e.provenance} (hooks ${risky.join(', ')}) because it is in allowMods`, 'debug')
      return next(e)
    }
    const reason = `GuardClaw refused mod ${e.provenance}: it hooks ${risky.join(', ')}, which can approve tool calls or rewrite stored rows. Add "${e.provenance}" to the guardclaw allowMods option to load it.`
    log($, reason, 'transcript')
    return { refuse: reason }
  }).catch(($, e) => ({ refuse: `GuardClaw could not check mod ${e.provenance}, so it was refused (fail closed).` }))
}
