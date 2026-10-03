# Architecture decision: one GuardClaw repository

Decision: use `TakeInterestInc/guardclaw-core` as the canonical existing repository
and **GuardClaw** as the provisional user-facing name. No remote repository, URL,
Go module, import path, original scanner CLI or public history is renamed.

Before: Core held the Go scanner and legacy Claude mod; Dot held the dashboard,
report helper/schema and a second copy of Core. Local candidates added Core
setup/hooks/receipts and Dot's capability-gated public-safe snapshot feed.

After:

- `guardian/`, `cmd/`, `go.mod`: one corrected scanner source, unchanged module.
  The imported `guardclaw-report` helper now imports this same source.
- `guardian/claudehooks`, `guardian/policy`, `guardian/receipts`: exact-tool
  Claude command-hook adapter and metadata journal; native permissions retained.
- `schemas/`, `internal/report`: existing advisory-report contract and validator.
- `observatory/`: read-only browser workspace, snapshot v1 and local spool.
- `tools/`, root `package.json`, README and SETUP: one setup/build/run/smoke/undo flow.

Only the scan-report contract, registry and receipt vectors cross language
boundaries. Snapshot v1 stays unchanged. Receipts are separate observations;
they never become task checks, approval, authority or execution proof. A local
browser import can check hashes against an owner-retained checkpoint. It cannot
authenticate the writer or establish unobserved host actions. The Go verifier is
the canonical verifier; the browser has a smaller 1 MiB/2,000-record limit.

Offline is the default. Live mode still needs explicit launch and selection of
a fresh owner-only capability; it accepts deliberately prepared public-safe
summaries only. Same-user processes, browser/extensions and privileged users
remain trusted. No official dots/Cowork API, account connection, orchestrator,
universal host adapter, concurrency/savings guarantee or automatic execution is
added. Automation recipes are future candidates until host capabilities and
measurements establish them.

History: import Dot's original local candidate as a merge parent and retain its
public merged head as ancestry, preserving authorship and the original trees.
The duplicated scanner disappears from the current tree, not from history.
Core's feature-only patch is applied above public Core PR17. Apache-2.0 LICENSE,
original notices, dependency notices and font OFL notices remain. Original
local patches/worktrees stay untouched. Historical verification/release records
are labeled archival; active setup points only to this product.

Publication is a separate reviewed step: inspect the exact candidate/tree and
diff, approve a branch push and draft PR to the existing canonical repository.
No remote rename, archive, delete, history rewrite or merge is in this scope.

Report baseline compatibility: the public Core engine adds one exported ID over
Dot's legacy registry. New reports use the verified public Core tree
`a0b591985209611ffc515a9ff676cea5eab83555` (1,704 IDs); legacy `336faa...`
reports remain accepted with exactly their former ID set (1,703). This is an
explicit engine-identity update, with unchanged report v1 shape, current/legacy
fixtures and generated-registry/actual-engine tests. No scanner code is modified.
