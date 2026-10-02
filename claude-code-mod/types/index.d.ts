// Copyright 2025-2026 TakeInterest Inc.
// SPDX-License-Identifier: Apache-2.0
//
// The guardclaw mod's contract: the one named value it keeps in `$.state`.
// Any plugin may read it; only guardclaw writes it.

/** Today's deny count, reset when the UTC day changes. */
export type GuardclawBlocked = { day: string; count: number }

declare module 'claude-code' {
  interface PluginState {
    guardclaw: { blocked: GuardclawBlocked }
  }
}
