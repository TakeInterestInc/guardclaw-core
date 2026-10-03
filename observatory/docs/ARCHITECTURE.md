# Architecture and data boundaries

A static browser app, Node built-in read-only loopback server, with no runtime package installation. Native ES modules and CSS are sufficient for this small surface. There is no database, model, SDK, account, hidden integration or runtime dependency installation. An explicitly enabled local feed adds same-origin loopback reads.

```text
Original synthetic fixture ───────────────┐
                                         v
Explicit safe JSON file → bounded parser → validated DTO → read-only views
                         (browser memory)    |             (textContent)
                                              └→ derived counts/freshness
```

`src/demo.mjs`: original authored fixture plus frozen evaluation time. `src/model.mjs`: pure schema checks, state consistency, freshness/filter/count helpers. `src/app.mjs`: small DOM primitives and view compositions; event handlers change local view/selection only. `styles.css`: shared tokens, continuous atmospheric field, editorial decision/proof grid and responsive boundaries. `assets/atmosphere-v1.png`: an original generated local texture. Decorative CSS motion has a pause control and reduced-motion fallback; it represents no live task state. `server.mjs`: exact route map, loopback Host check, GET/HEAD only, no-store and restrictive CSP: `connect-src 'none'` by default, `'self'` only with `--live`. Static example files are safe; docs/tests/private files are not served.

Manual browser imports never go to the server. No localStorage, sessionStorage, IndexedDB, cookies, analytics, externally fetched fonts/assets, sockets or operational mutations are used by the app. Fetch is used only by the explicitly connected local feed, to one same-origin fixed route. The optional test runner performs local HTTP reads/negative checks; it is outside app runtime.

## Optional local feed

`tools/local-feed.mjs` validates and atomically publishes snapshot v1 on stdin to a fixed owner-only spool. With `--live`, the loopback server serves only bounded, revalidated snapshots through a per-launch-capability GET/HEAD endpoint. The fresh random capability is atomically published to an owner-only access file after successful listen, selected explicitly into browser memory, and checked before every read/cache response. Reset/reload clear browser capability; restart invalidates old capabilities. It never appears in URLs/logs or static routes. It denies foreign Host/Origin and cross-site Fetch Metadata; no CORS, arbitrary paths/URLs or network writes exist. The browser polls serially only after an explicit connection and stops on reset/reload/manual snapshot selection. It preserves the last good snapshot on failure, updates freshness, distinguishes capture from receipt time, and advances the advisory association revision only on changed snapshots. No hashing, authenticity, execution or enforcement is established. See [LOCAL_AGENT_SETUP.md](LOCAL_AGENT_SETUP.md).

## Future account adapter seam

A separately reviewed adapter may transform a supported, authorized API's public-safe records into the version 1 DTO. It must live outside the reusable UI package, hold credentials outside snapshot data, enforce source/task scopes and owner authorization, retain observation/capture times, and pass the same validation. A producer claiming `authorized-api` does not establish authorization. No private state scraping, raw-log translation or automatic credential discovery is acceptable.

The canonical Core source lives at the repository root with its unchanged Apache LICENSE/NOTICE and dependency notices; no scanner copy is bundled here. An operator builds and runs its stdin-only helper manually; there is no execution route, runner, bridge or automatic download. `src/guardclaw-report.mjs` is an Apache-2.0 strict validator port, with a generated 1,704-current / 1,703-legacy ID registries in `src/guardclaw-patterns.mjs`. Only these exact static modules are served; the Core tree, binary, fixtures, schema and docs are not HTTP routes.

The browser owns one random session snapshot UUID and a safe-integer revision. Every successful snapshot replacement/reset advances the revision; failed replacements do not. Reports are separate memory-only sidecars with application import times, always unverified provenance and selected-content association. Earlier/mismatched reports remain visibly noncurrent. A null subject is an unattached metadata error. Reports never enter snapshot v1, evidence arrays, task states or derived verified counts. No-match has no authority. Reset cancels pending reads and discards reports; overlapping reads use generation tokens to preserve the latest explicit selection. See SCANNER_REPORTS.md.

## Public/private separation

The public-safe candidate consists of original code/composition, synthetic fixtures, generic docs, optional separately licensed Core source/validator/registry, and three unmodified OFL font assets with their full notices, and one original generated texture with recorded provenance. The font/palette roles are recorded in BRAND_PROVENANCE.md. Internal process records and review metadata are retained locally in the task's evidence packet; never included in the public-safe release archive. Any later private fixtures/adapters belong outside this folder. `.gitignore` excludes conventional secrets/private imports/test outputs, but an ignore rule is not a disclosure guarantee; review the exact archive and repository history before release.
