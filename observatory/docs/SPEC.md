# Snapshot dashboard specification

Product: GuardClaw (provisional name), observatory component in the existing guardclaw-core repository. Design intent: orient through a decision, its proof and recent work.

## Product contract

The person reviewing a snapshot can answer: what needs attention, what was implemented, what has supporting checks, what needs the owner, and how recent the source is. A snapshot is a producer's report. The dashboard checks shape and consistency; it does not independently verify claims or authorize actions.

Work tab: derived snapshot totals, local search, attention/stage filters, task list, selected task inspector. Decisions tab: the selected actual question leads an editorial/proof grid; ruled buttons select one pending recommendation, rationale, trade-offs, disagreement, source and linked task. Resolved outcomes remain available below the continuous work band. Evidence tab: all check records and reported outcomes. Data & safety tab: explicit local import and reset, schema guidance, provenance and runtime boundaries.

Demo includes six wholly synthetic tasks, two blockers, two pending owner decisions, a verified claim with dated passing evidence, a failed check, stale observations and unknown observation/progress. Fixed demo evaluation time prevents invented live freshness. Imported snapshots use the actual opening time once; the time remains visible and can be recalculated manually.

## Data distinctions

- Status: planned, active, blocked, done, unknown.
- Stage: proposed, implemented, verified. Stage describes reported evidence, independent of operational status.
- Progress: completed/total checklist items; null means unknown. No estimated percentage without a checklist.
- Freshness: fresh within 60 minutes, stale after 60 minutes, unknown when absent. Observation cannot follow capture; capture cannot be materially in the future.
- Evidence: passed, failed, pending. A verified stage requires at least one dated passed check belonging to the task. This is a consistency check, not a guarantee of correctness.
- Sources: synthetic, manual, authorized-api. Source labels/IDs are producer declarations. URLs are optional, strictly restricted HTTPS and always inert in this prototype.
- Owner choices: awaiting-owner or resolved; resolved decisions require outcome text. No operational approval buttons.
- Recommendations are authored records with short public-safe rationale and trade-offs, never model internals.

## Acceptance

Acceptance scenarios are covered by model tests, browser checks and the measured results in VERIFICATION.md. No private corpus content is bundled. No external requests, imported HTML, saved local data, hidden credentials, active external links, or mutations. Responsive at 375/390px and desktop 1440px. Keyboard reaches every action, focus is visible and selection exposes context. Import rejection preserves last good snapshot and avoids echoing raw payload.

## Unknowns/deferred

Any supported live dots task export API (none is public today)  and GuardClaw enforcement are unestablished. Real authorization, account integration, encryption at rest, continuous refresh, collaboration, public feedback collection, and the exact repo destination are deferred. Other users' needs have no evidence yet; the offline feedback template is the next research step. Synthetic recommendation language is illustrative only.
