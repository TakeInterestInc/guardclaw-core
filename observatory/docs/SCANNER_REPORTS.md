# Optional report sidecar

The snapshot v1 schema/model is unchanged. Reports never become task evidence, checklist progress, decisions or verification status. The app does not scan a snapshot automatically or export its data. An operator explicitly builds/runs the included helper on selected safe text, then explicitly imports its report.

`../../schemas/guardclaw-scan-report.v1.json`, the fixed 1,703-ID registry and `../../internal/report/validate.go` define the contract. The browser port rejects duplicate keys before ordinary object parsing, integer decimal/exponent notation, unsafe integers, UTF-8/BOM errors, containers beyond depth six, oversized 64 KiB reports, unknown keys/engine/IDs, contradictory counts, timestamps and finding lines. No arbitrary error messages, selected snippets, file paths, hashes or URLs are allowed. Fixed error codes are displayed without raw parser messages or filename.

Each page session gets one generated UUID and starts at revision zero. A successful whole-snapshot replacement advances revision even for identical bytes; rejected imports preserve context. Reset advances revision and discards report/snapshot imports. View/selection changes and freshness rechecks do not advance revision. Reload creates a new UUID and discards all imports. Overlapping/pending imports use generation tokens; reset invalidates pending selections.

A report is current only when declared UUID/revision match. Earlier revisions are labelled stale association; other UUIDs/future revisions are unattached mismatches. Null subject is allowed only for INVALID_METADATA failure, and stays unattached. Every state remains user-imported and unverified, including apparently current reports. Reported start/finish and application import time are separate; age is evaluated at render and marked stale after one hour or future beyond five minutes, without polling or authentication. Coverage is only the manually selected text, never a claim about the task or all repository files.

Complete/no-match means no known static patterns matched selected lines. Complete/findings means review needed. No-content/failure means unknown. None grants authority or passes a task check. Invalid replacement preserves the prior report. Remove/reset/reload discards memory; no upload/persistence/export/execution exists.

The optional helper accepts stdin and generated metadata, with 256 KiB input, 1,000 lines, 16 KiB/line, 200 findings, 16 IDs/finding, 64 KiB output and 10-second watchdog. Exit 0=no-match, 1=findings, 2=failure/no-content. Missing/truncated output must be rejected. Its static scan path makes no network/feed/model/exec calls, but OS network containment was not independently established; hard memory containment is not claimed. Cross-platform runs are untested.

The demo needs only Node/browser. Optional source build needs Go 1.26.6+ and may fetch standard dependencies if uncached. Full Apache Core and Go dependency notices are retained. No proprietary runtime, binary, private test receipts/history or data are shipped. The Apache browser port/registry are separately licensed from the original dashboard; the dashboard and Core retain Apache-2.0, with separate font OFL notices.

## Consolidated baselines

New reports use public Core tree `a0b591985209611ffc515a9ff676cea5eab83555`
and its generated 1,704 IDs. Existing `336faa083fccb78a098cf2cf146df3e4d50c1d82`
reports remain importable against their original 1,703-ID registry. No baseline
authenticates a scanner or proves an input safe. Run `go run ./tools/generate-registry`
from the root after a reviewed scanner change, then test actual-engine/registry
parity and both browser contract sets. Removing legacy IDs needs a reviewed migration.
