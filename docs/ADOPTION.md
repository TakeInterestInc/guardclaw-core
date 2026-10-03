# Adoption visibility

Use the existing canonical GitHub repository's aggregate stars, forks, release
asset downloads and maintainer traffic views/clones. Record the metric, date and
scope. These measure interest or retrieval, not verified active installations,
unique people or active users. Clones can include CI/repeated retrievals, and a
source checkout has no release-asset download event. Do not infer a user count
from stars or claim comparative superiority from an unidentified hackathon entry.

Optional future setup event proposal: `guardclaw.usage.v1`, `setup_succeeded`,
public `version` only. `tools/adoption.mjs` is a pure, disabled-by-default event
factory tested with synthetic data. Setup does not invoke it. No transmitter,
endpoint, vendor, persistent ID, local analytics file or backend exists. It
cannot count installations or users, and does not transmit anything.

Before any later collector is implemented, the owner must review the specific
endpoint, retention/aggregation policy and a concrete consent preview. Each user
must choose it explicitly; refusing must preserve full functionality. No prompt,
command, host identity, project/private path, tool name, account, credential,
receipt or snapshot data belongs in a usage event. Offline remains the default.
