> Historical Dot component record. Current product/setup: [root README](../../README.md).
> These observations predate consolidation and do not certify this candidate.

# Repository setup

Published at <https://github.com/TakeInterestInc/dot-observatory> (public, created 2 October 2026). Repository settings were applied on 2 October 2026. The table below is the GitHub API readback from that day, not the proposal; where the two differ, the gap is listed underneath. Re-read the settings before relying on any row.

## Applied settings (API readback, 2 October 2026)

| Control | Applied state |
| --- | --- |
| `main` changes | Pull request required; force pushes and deletion blocked |
| Required approving reviews | 0 |
| Required status checks | None bound |
| Enforce for administrators | Off |
| Required conversation resolution | Off |
| CODEOWNERS | None in the repository |
| Private vulnerability reporting | Enabled (Security tab, Report a vulnerability) |
| Allowed actions | GitHub-owned actions only; full-SHA pinning required |
| Default workflow token | Read; Actions cannot create or approve pull requests |
| Fork pull request workflows | Approval required for all external contributors |
| Hosted CI | `model-tests` ran on GitHub Actions (app `github-actions`, id 15368) and passed on the first `main` push |

## Gaps against the proposed protection

These proposed controls are not in place yet. Each needs an owner decision and, for reviews, a second maintainer:

- Bind `model-tests` as a required check to the observed `github-actions` app (id 15368), with an up-to-date branch.
- One approving review from a maintainer other than the author; dismiss stale approvals; require approval of the latest push by someone other than its pusher.
- Required conversation resolution, and enforcement for administrators with no bypass actors.
- CODEOWNERS covering `.github/workflows/`, package and test scripts, server and import validators and license/provenance files, added only after maintainers' real GitHub identities are verified. No placeholder account, no automated approving bot. One maintainer cannot approve their own change.

After any change, verify by readback and run a real fork pull request against the merge block. [GitHub protected-branch controls](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches).

## Lean CI

The workflow runs built-in Node model tests and syntax checks on normal `pull_request` and `main` push events. It has `contents: read`, disables checkout credential persistence, passes no secrets and has no deploy or publish step. Use hosted runners. Never execute fork code in `pull_request_target` or a write-token workflow. It does not claim browser, Safari or device coverage, and it does not run the Go tests at the repository root; run `go test -race ./...` there.

Full SHA pins were checked against official release commit pages on 2 October 2026: [checkout v7.0.1](https://github.com/actions/checkout/commit/3d3c42e5aac5ba805825da76410c181273ba90b1), [setup-node v7.0.0](https://github.com/actions/setup-node/commit/820762786026740c76f36085b0efc47a31fe5020). Node 22 is a fixed test target. No package installation or dependency cache is needed.

The workflow declares only `contents: read`, so unspecified scopes, including contents write, PR write and OIDC, are absent. Tests execute contributor-controlled code in the disposable hosted runner with no supplied secrets; a green check is not a trusted code review. Inspect workflow, package and test changes before approving a run or merge. No `pull_request_target` or `workflow_run` path processes untrusted source or artifacts. [Token permission semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions), [untrusted-workflow guidance](https://docs.github.com/en/actions/reference/security/secure-use).

## Releases

Review exact staged files and history before each release. Retain font notices and asset provenance; the root LICENSE is Apache-2.0 unless the owner changes it. A release should identify a version and exact commit, include run and test steps, and state unsupported integrations and device coverage.

## Capability needed for further settings changes

Branch protection changes require repository admin access, or a repo-scoped GitHub App or fine-grained token with **Administration: write**; readback needs Administration: read. No secret needs to be stored in this repository for that. Present the exact settings for approval before changing them. [Protection API permissions](https://docs.github.com/en/rest/branches/branch-protection#update-branch-protection).
