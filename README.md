# Dot Observatory 0.2.1

A compact, read-only way to compare owner decisions, recommendations, trade-offs, task blockers and reported evidence across parallel work. Starts with entirely synthetic authored data, or a JSON snapshot you import by hand. An opt-in local feed can receive deliberately prepared public-safe summaries from a capable local agent producer. This is a first draft: no official dots/Cowork or account API is wired, no existing agent state is discovered, and nothing is hosted. Licensed under [Apache-2.0](LICENSE).

Native dots Activity already shows delegated task progress, files, results and requests for input. This project tests whether a compact decision/evidence view and explicit freshness labels help beyond the native UI and a short guide. It is not a replacement task runtime or security gateway.

## Run in one minute

Requires an installed Node.js 20+ and a modern browser. No package install, account, API key, paid service or internet connection is needed to run the app.

```sh
cd dot-observatory
npm start
```

Open **http://127.0.0.1:4317** on the same computer. Stop with **Ctrl+C**. If the port is occupied, use `PORT=4318 npm start` and open that port. The server binds explicitly to loopback and serves only app/example routes. Do not expose it with a tunnel or reverse proxy. `file://` loading is unsupported because this app uses native ES modules.

Phone-sized layouts are implemented and tested in Chromium emulation. The loopback URL is not accessible from a separate iPhone; screenshots saved to private Library are previews, not a hosted app. Actual iPhone/Safari validation remains pending.

Measured viewport previews: [desktop decision](docs/screenshots/desktop-decisions.png), [390px decision](docs/screenshots/iphone-390-decisions.png), [390px stale inspector](docs/screenshots/iphone-work-stale.png). These show the synthetic frozen snapshot, not live work.

## Try the local connection

Run `npm run start:live`, open the printed loopback URL, and in **Data & safety** choose this launch’s `.observatory-local/access.json`, then select **Connect local feed**. In a second terminal in this project, run `npm run demo:agent` to see four synthetic updates. This is a **synthetic adapter demo**, not an official host integration. Checks and outcomes remain unverified producer claims.

[Local agent setup](docs/LOCAL_AGENT_SETUP.md) gives agent-readable onboarding, the fixed snapshot v1 contract and the security boundary. A capable local producer can explicitly publish prepared summaries; no raw agent logs, credentials, account connection, persistent hook or command execution is involved. The default `npm start` remains offline.

## Two-minute trial

1. On **Owner decisions**, the actual pending question leads. Select a ruled decision row to compare another choice; read its recommendation, its short authored rationale, the trade-off, and disagreement. These summaries are public-safe records, not private model reasoning.
2. Select **Inspect task** to compare the blocker and proposed/implemented/verified stage with the source and check evidence.
3. In **All work**, choose **Needs attention** and find a stale or unknown observation. Check the visible timestamp; process presence does not establish progress.
4. In **Evidence**, compare passed, failed and pending checks.
5. In **Data & safety**, optionally select `examples/empty.json` or `examples/snapshot.json`. Imported data stays in memory and disappears on reset/reload. An old imported fixture becomes stale at the actual opening time; the synthetic demo uses its explicitly frozen time.
6. Record feedback in [docs/FEEDBACK.md](docs/FEEDBACK.md). There is no submission endpoint or telemetry.

For help using dots now, read [docs/DOTS_QUICK_START.md](docs/DOTS_QUICK_START.md).

## Optional local Core scanner

The demo works without Go or a scanner. GuardClaw Core is being prepared as its own repository; once it is published, this folder will point at that public Core repo. Included [`guardclaw/`](guardclaw/REPORT-QUICKSTART.md) source builds a manual local stdin-to-report helper with Go 1.26.6+. No helper binary is distributed or executed by the dashboard.

1. Build once: `cd guardclaw` then `go build -trimpath -o guardclaw-report ./cmd/guardclaw-report`; return to this repository root.
2. In **Data & safety → Optional local scan**, select **Prepare local scan** and copy its session UUID/input-revision command. Manually choose only safe local text you are authorized to scan and replace the synthetic filenames.
3. Run that command yourself. Exit 1 is an importable findings report; exit 2, missing or truncated output means unknown. Do not use an `&&` chain that drops findings.
4. Open the report in that same panel. It stays in browser memory, separately from snapshot v1 and task check evidence. Current association, earlier revision, mismatch/unattached errors, reported/import times and selected-line coverage remain explicit. Reset/reload discards reports; replacing a snapshot advances its revision even for identical content.

No-match never proves safety, passes a task check or authorizes work. Scanner/input identity is unverified. Core uses static patterns; network containment is **unverified**. See [report boundaries](docs/SCANNER_REPORTS.md). Go dependencies may need downloading on an uncached build; no scanner or Go dependency is needed to use the demo.

Changed scanner previews: [desktop](docs/screenshots/desktop-scanner-report.png), [390px report](docs/screenshots/iphone-scanner-report.png). These are synthetic unverified report examples.

## Checks

```sh
npm test
```

The app needs no runtime package installation. The optional report validator and static registry are Apache-2.0 ports/data from the included Core source, separate from the original dashboard code. Its original atmospheric texture is local; pause its decorative motion with the masthead control, or enable reduced motion. Three bundled OFL fonts provide the requested typography; their complete notices are included. Optional browser QA uses an already installed Playwright and axe-core. No installation is performed by this project. To use tooling available elsewhere:

```sh
PLAYWRIGHT_MODULE=/absolute/path/to/playwright/index.mjs \
AXE_PATH=/absolute/path/to/axe-core/axe.min.js \
npm run test:ui
```

Run `npm run test:scanner-ui` with the same optional Playwright/axe environment for report integration checks. Start the server first. Optional `DASHBOARD_URL` and `EVIDENCE_DIR` change the test target/output. Browser results and screenshots live in `evidence/`. See [docs/VERIFICATION.md](docs/VERIFICATION.md) for measured results and limitations. Real Safari, VoiceOver, live APIs and GuardClaw enforcement are not established by Chromium tests.

## Boundaries and documents

- [Specification](docs/SPEC.md), [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md).
- [Safe import contract](docs/IMPORT_SCHEMA.md): strict version 1 DTO, explicit local file selection, bounded input, text-only rendering, inert URLs. Common credential patterns are rejected; detection is partial. Only intentionally prepared public-safe files belong here.
- [Prospective release checklist](docs/RELEASE_READINESS.md), [dependency/license inventory](docs/THIRD_PARTY.md), [brand provenance](docs/BRAND_PROVENANCE.md).
- No private dot memory, orchestration state, prompts, raw session logs or credentials are included. Local corpus guidance informed the process only; no private corpus excerpts or proprietary third-party implementation is bundled. Optional Apache Core source and its derived report validator/registry are included with notices. The explicitly requested TakeInterest visual identity uses licensed font bytes and verified color/type tokens in an original dashboard composition.

The default server reads static allowlisted public-safe files. Manual browser imports never reach the server. With explicit live mode and connection, a fixed local spool supplies revalidated snapshots. There are no operational approval, execution, messaging or deployment controls. Reported verified stage requires dated passing evidence, but this app does not authenticate its source or rerun checks.

Repository contribution/report templates, trust boundaries and proposed maintainer settings are in [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [docs/MAINTAINER_SETUP.md](docs/MAINTAINER_SETUP.md). Imported snapshots are producer claims: a source labeled `authorized-api` is a label the file author typed, not a connection this app makes.
