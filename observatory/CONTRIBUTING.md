# Contributing

This project is licensed under Apache-2.0 (see LICENSE). Contributions are accepted under the same license.

Keep changes small and reviewable. Preserve the synthetic, read-only quickstart and the separation between UI records and any separately authorized adapter. Discuss new integrations before implementation. Do not add credentials, telemetry, private state readers, agent logs, hidden instructions or operational authorization controls.

## Prepare a change

1. Use Node.js 20+; run `npm test`. No dependency installation is needed for the app or model tests.
2. Run `npm start`, open http://127.0.0.1:4317, and inspect the affected view. Stop with Ctrl+C.
3. Check desktop and 375/390px layouts, keyboard focus, long strings and reduced motion for presentation changes. Optional installed Playwright/axe setup is documented in README.md. Report unavailable coverage honestly.
4. Open a small pull request explaining the problem, behavior change and exact checks. The PR template is a guide; delete irrelevant sections.

Use only authored synthetic examples in tests and reports. Never attach session logs, imported personal/work data, credentials, private screenshots or internal paths. Reproduce a bug with the bundled examples or a small synthetic file. Reports of security issues belong in the private route described in SECURITY.md once a real channel is configured.

Changes require maintainer review and passing checks. Fork CI uses a read-only token and no secrets. Do not introduce `pull_request_target`, credentialed execution of fork code, self-hosted runners or publication steps. Keep adapters optional and separate; a producer label never authenticates a source or proves enforcement.
