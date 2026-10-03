> Historical Dot component record. Current product/setup: [root README](../../README.md).
> These observations predate consolidation and do not certify this candidate.

# Verification — 0.2.1

Measured on 2 October 2026 using macOS, Node 25.8.2, installed Playwright 1.62.1 / Chromium 151.0.7922.34 and axe-core 4.12.1. No dependency installation or paid service was required. The loopback server used the normal reviewed sandbox permission path.

| Check | Result |
| --- | --- |
| Unchanged model suite | 12 passed, zero failed |
| Current shipping browser suite | 13 functional groups passed; four axe views had zero reported violations |
| Extended regression | 14 functional groups resolved; 12 responsive axe scans and four zoom-emulation scans had zero reported violations |
| Keyboard and touch targets | Four desktop views and eight phone view states covered; final phone targets at least 44×44px, sampled focus contrast at least 4.525:1 |
| Responsive layout | 1440×1024, 390×844 and 375×844; no observed page overflow; inspector clears the sticky snapshot identity |
| Import boundaries | Empty/error/last-good/reset/reload, inert HTML/URLs, known credential patterns and long strings passed |
| Runtime boundaries | Zero external page requests or runtime errors; empty storage/cookies/databases/caches/service workers |
| Decorative field | Exact local PNG route, pause/resume and reduced-motion checks passed |
| Fonts and server | Actual custom glyphs; local routes/MIME/HEAD, restrictive CSP and negative Host/method/query checks passed |

The final canonical suite was observed at 07:20:28 UTC. Extended coverage combines its baseline with affected reruns; it is not one fresh complete pass of every check against one final hash. The separate source-repository copy also passed its 12 model tests. GitHub CI (`model-tests`) has since run on GitHub Actions and passed on the first `main` push, 2 October 2026.

Independent visual review accepted the approved structural direction at desktop and 375/390px. The author inspected final captures. One Evidence focus-ring/text collision was corrected with spacing; a skip-link halo and 44px minimum button width improve focus/touch handling. Named groups have explicit semantics. Raw findings and corrected font/pixel-probe harness errors remain in the private local evidence packet.

Viewport previews represent the continuous fixed background and sticky context more faithfully than full-page capture, which can relocate fixed elements. The generated texture is decorative, never a live progress signal.

Limits: physical iPhone, Safari, VoiceOver and clean-machine onboarding remain untested. 200% text resize passed; zoom was emulated at 720×512 CSS pixels with scale factor two. Axe retains some contrast incompletes on small counts/decorative glyphs; the mobile Evidence summary has a conservative contrast bound of 8.106:1. Finite captures do not certify every animation frame or accessibility conformance. Sources are unauthenticated and credential detection is partial. No live account adapter, GuardClaw enforcement or public deployment is implemented or tested. Release terms and publication remain pending.

The synthetic check records displayed inside the app are authored examples, not tests of this prototype.

## Combined optional scanner — 0.2.1

On 2 October 2026, 30 Node model/report tests passed, including all 15 Core contract fixtures plus strict token/UTF-8/depth/malicious-field edge cases. Final shipping browser suite passed 13 functional groups and four axe views. Focused scanner suite passed nine groups and three axe scans at 1440/390/375px: matching/earlier/mismatch/failure/no-content, malicious/oversize/UTF-8/duplicate replacement, last-good preservation, snapshot revision/reset/pending-read cancellation, report removal/reload, targets and memory/network boundaries. No runtime errors or external page requests.

Included source built offline on Mac arm64 with cached Go 1.26.6: full test/vet/trimpath build passed. Actual rebuilthelper no-match/findings/empty reports exited 0/1/2 and all parsed by browser validator. Independent source reviewer ran 30 Node tests, verified all 1,703 registry IDs and found no blocker; browser/Go/archive checks were reviewed as recorded evidence rather than independently rerun. Two small documentation inconsistencies were corrected.

Changed [desktop](screenshots/desktop-scanner-report.png) and [390px report](screenshots/iphone-scanner-report.png) viewport previews show handcrafted synthetic imported reports; current declared association remains unverified. No physical iPhone/Safari/VoiceOver, authenticated source proof, OS network containment or cross-platform helper execution is established. These checks provide no task approval/security enforcement.
