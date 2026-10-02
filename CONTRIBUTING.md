# Contributing to GuardClaw Core

Thanks for your interest in improving GuardClaw Core. This project is the open detection engine for AI-agent security, and community contributions — new attack patterns, false-positive fixes, performance work, and integrations — are welcome.

## License of contributions

GuardClaw Core is licensed under [Apache License 2.0](LICENSE). By contributing, you agree that your contributions are licensed under the same terms (Apache-2.0, §5: contributions are submitted under the license of the project unless you state otherwise).

## Developer Certificate of Origin (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/) instead of a CLA. It is a lightweight, one-line attestation that you wrote the contribution (or have the right to submit it) and that it may be distributed under the project's license.

Sign off every commit by adding a `Signed-off-by` line — `git commit -s` does this automatically:

```
Signed-off-by: Your Name <you@example.com>
```

CI (`.github/workflows/ci.yml`, job `dco`) checks that every non-merge commit
in a pull request carries a `Signed-off-by:` line. It checks that the line is
present, not that the name matches the commit author.

## How to contribute

1. **Open an issue first** for anything non-trivial, so we can align on approach before you invest time.
2. **Fork + branch** from `main`.
3. **Add a test.** New detection patterns must include both a positive case (the attack is flagged) and a benign case (a similar-looking safe input is *not* flagged). False positives are bugs.
4. **Run the suite locally** (see below) — it must be green.
5. **Open a PR** with a clear description and `git commit -s` sign-off.

## Detection patterns: the quality bar

A good pattern detects a real attack class without flagging legitimate use. Every new pattern is evaluated against the corpus in `testdata/corpus/`:

- **Benign corpus** — the fraction of inputs receiving `deny` must stay at or below 1%; escalations are not counted by this test.
- **Malicious corpus** — the fraction receiving a non-`allow` decision must stay at or above 95%; this includes escalations.

These are rates on the checked-in samples, not guarantees for real agent inputs.

If your pattern raises false positives on the benign corpus, it needs narrowing. If it adds a new attack class, add representative samples to both corpora.

## Build & test

```sh
go version          # Go 1.26.6 or newer
go build ./...
go test -race ./...  # includes the corpus false-positive / detection evals
go vet ./...
gofmt -l .           # must print nothing
```

CI runs the same `gofmt`, `go vet` and `go test -race` on every push to `main`
and every pull request.

Tests scan corpus lines as text and do not execute their sample commands.
Read test code from a contribution before running it on your machine.

Credential-shaped samples must have documented synthetic construction; do not
copy real logs or credentials into the corpus. See `testdata/corpus/README.md`.

## Reporting security issues

Do **not** open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md) for private disclosure.

## Code of conduct

Be respectful. Assume good faith. We follow the [Contributor Covenant](https://www.contributor-covenant.org/).
