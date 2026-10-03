# Dependency and license inventory

No icon sets or installed browser runtime packages are shipped. Optional Apache Core source and a derived browser validator/registry are included. One original generated atmospheric image is bundled; no TakeInterest image bytes are used. Three unmodified OFL fonts are bundled. The browser app is original HTML/CSS/JavaScript; the server uses Node built-ins. The consolidated source uses Apache-2.0; font assets retain OFL 1.1.

| Component | Role / observed version | License status | Shipped? |
| --- | --- | --- | --- |
| Original application/server/docs | Candidate 0.2.1 | Apache-2.0 (root LICENSE) | Yes, in candidate |
| Canonical Core source at repository root | One scanner implementation unchanged from public `0052c301400c91f615d93d0605485f8b1bff4059`; Dot's report helper now imports it. Current registry tree `a0b591985209611ffc515a9ff676cea5eab83555` has 1,704 IDs; original 1,703-ID baseline remains accepted for report compatibility | Apache-2.0; root LICENSE and original attribution retained | Yes, source only |
| `src/guardclaw-report.mjs`, `src/guardclaw-patterns.mjs` | Validator port and generated 1,703-ID registry | Apache-2.0, explicit SPDX headers; same Core LICENSE/NOTICE apply | Yes |
| aho-corasick | Optional helper Go dependency v1.0.3 | MIT; full notice under `../../third-party-notices/` | Notice/lock references only |
| golang.org/x/text | Optional helper Go dependency v0.40.0 | BSD-3-Clause and PATENTS; full notices under `../../third-party-notices/` | Notices/lock references only |
| Go | Optional helper build runtime, 1.26.6 tested | BSD-3-Clause/PATENTS; complete build-runtime notices included | Notices only, no binary |
| Original atmospheric texture | Built-in ImageGen, 2 October 2026 | Generated for this project; covered by the root Apache-2.0 LICENSE unless the owner states otherwise | Yes |
| actions/checkout | CI pin v7.0.1, full SHA in workflow | MIT, official pinned LICENSE | Reference only; action code not bundled |
| actions/setup-node | CI pin v7.0.0, full SHA in workflow | MIT, official pinned LICENSE | Reference only; action code not bundled |
| Node.js | Installed runtime, v25.8.2 used for QA; 20+ supported target | Node project has MIT and bundled third-party notices; not vendored | No |
| Bricolage Grotesque | Display font; embedded version 1.001, 2022 project copyright | SIL OFL 1.1, full `fonts/licenses/Bricolage-OFL.txt` | Yes |
| Geist | Body font; embedded version 1.800, 2024 project copyright | SIL OFL 1.1, full `fonts/licenses/Geist-OFL.txt` | Yes |
| Geist Mono | Utility font; embedded version 1.700, 2024 project copyright | SIL OFL 1.1, full `fonts/licenses/Geist-Mono-OFL.txt` | Yes |
| Browser/system fallback fonts | Platform runtime fallback | Platform licenses; not redistributed | No |
| Playwright | Optional installed QA, 1.62.1 | Apache-2.0 per installed package metadata | No |
| playwright-core | QA transitive, 1.62.1 | Apache-2.0 per installed package metadata | No |
| axe-core | Optional installed accessibility QA, 4.12.1 | MPL-2.0 per installed package metadata | No |
| Chromium | Installed Playwright QA engine; exact engine version in browser-results.json | Chromium project BSD-style plus third-party notices; no browser binary copied | No |

The local QA tools are not package dependencies and are not bundled in the source candidate. Reproducible future CI should pin versions and retain their notices before installing or redistributing. The original small favicon is code-native SVG authored here; no third-party mark is used.

## Font provenance

Bricolage copyright belongs to the Bricolage Grotesque Project Authors; Geist and Geist Mono to the Geist Project Authors. The bundled WOFF2 assets match the fonts in the explicitly requested TakeInterest homepage and were not modified. Full matching notices were obtained from official project sources: [Bricolage](https://raw.githubusercontent.com/ateliertriay/bricolage/main/OFL.txt), [Geist](https://raw.githubusercontent.com/vercel/geist-font/main/OFL.txt), [Geist Mono](https://raw.githubusercontent.com/google/fonts/main/ofl/geistmono/OFL.txt). The OFL applies to these font assets, not to the original dashboard code. Preserve these notices if distributing the candidate. See BRAND_PROVENANCE.md for color and typography roles.

## Precedents, not dependencies

Official repository docs were inspected to avoid overstating novelty: [Mission Control](https://github.com/builderz-labs/mission-control) describes a self-hosted agent control plane; [Agent Workboard](https://github.com/ventus-software-solutions/agent-workboard) describes a local project/task board; [Agent Inbox](https://github.com/langchain-ai/agent-inbox) describes an inbox for human-in-the-loop agents; [Langfuse](https://github.com/langfuse/langfuse) describes agent evaluation/observability. No code, designs, assets or dependencies from those projects were copied. Their licenses do not license this candidate.

GuardClaw is the provisional combined product name. Core and the original Dot
component retain Apache-2.0 and their attributions. The duplicated Core source
has been removed from this component's current tree; source history is preserved.
OFL font grants and notices remain separate.

CI license references: [checkout pinned LICENSE](https://raw.githubusercontent.com/actions/checkout/3d3c42e5aac5ba805825da76410c181273ba90b1/LICENSE), [setup-node pinned LICENSE](https://raw.githubusercontent.com/actions/setup-node/820762786026740c76f36085b0efc47a31fe5020/LICENSE). These action licenses do not select release terms for this application.
