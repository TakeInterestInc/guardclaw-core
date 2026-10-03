<!-- SPDX-License-Identifier: Apache-2.0 -->
# Optional local advisory report

This scanner is included as source. The bundled synthetic report examples can be previewed without building Go; dashboard report import is in Data & safety → Optional local scan. To scan your own explicitly selected local content, use an existing Go 1.26.6+ installation and build this directory once:

```sh
go build -trimpath -o bin/guardclaw-report ./cmd/guardclaw-report
./bin/guardclaw-report --snapshot-id 00000000-0000-4000-8000-000000000001 --revision 7 < examples/advisory/review-needed.txt > review.report.json
```

Exit **1** means a complete report has findings: still import it for review. Avoid `&&` chains that skip import on findings. Exit 0 means no known patterns matched selected lines; exit 2 means failure or nothing scanned. A timeout/cancellation/write failure can leave no report or truncated JSON; reject it. Go may need its standard dependencies to build if they are not already cached; scanner execution itself loads no network/feed/model/config and requires no account, daemon or installation outside this directory.

For actual snapshot association, replace the synthetic UUID/revision above with the dashboard's “Prepare local scan” metadata shown there. Selected content's relationship to the snapshot remains operator supplied and unverified. Scanner output never grants action authority or blocks a tool. Other assistants can run this same explicit local command; there is no hidden dots hook.

The helper reads stdin only. It exports no selected content, snippets, paths, source hashes or arbitrary parser/engine messages. Limits: 256KiB input, 1,000 lines, 16KiB per line, 200 findings, 16 IDs per finding, 64KiB output, 10-second watchdog through blocked input/output and termination. Memory accounting is advisory; no hard RSS containment is claimed. Comments are scanned; blank input is unknown. Reports are forgeable and always unverified.

Report contract: `schemas/guardclaw-scan-report.v1.json` plus the mandatory strict-parser/semantic/attachment checks implemented in `internal/report/validate.go`. `schemas/conformance-cases.json` includes handcrafted synthetic validator fixtures. `examples/advisory/*.report.json` are observed output from the included synthetic inputs; they still are unverified imported reports. The dashboard uses a separate memory-only advisory panel and never marks task checks passed. See observatory/docs/SCANNER_REPORTS.md.

```sh
go test ./...
go vet ./...
```

This repository remains Apache-2.0 under LICENSE and NOTICE. Full dependency
notices remain in third-party-notices/. The dashboard's validator is a port;
the scanner implementation is shared with the original CLI and hook library.
