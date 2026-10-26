# Changelog

## 0.1.0 (2026-10-27)

First public release.

### Recorder
- Records every hook event (prompts, tool calls, decisions, results, sessions) in a local SQLite ledger (`~/.agent-ledger/ledger.db`, WAL mode, private file permissions).
- **Tamper-evident hash chain** (SHA-256, or HMAC with a key you keep). `verify` names the first broken link, and also catches truncation and checks against anchored head hashes.
- **Secret redaction in layers** before anything is written:
  - known token formats, URL credentials, auth headers and `KEY=value` assignments;
  - high-entropy and hex strings;
  - commands where quotes split a secret;
  - secret files, whose contents are dropped entirely.

### Policy gate
- A TOML policy decides allow, ask or deny before each tool call. The first matching rule wins, and the strictest part of a shell command wins.
- **Shell normalisation**, so tricks don't hide commands:
  - quotes and ANSI-C strings, `$IFS` and braces;
  - command substitution, here-docs, and wrappers (`sudo`, `env`, `xargs`, `timeout`, …);
  - nested shells, `eval`, and `find -exec`.
- **Starter policy:**
  - denies destructive deletes and writes outside the project, secret files, `curl | sh`, force-pushes to main and `chmod 777`;
  - asks for pushes, installs, migrations, infrastructure, deploys, unlisted domains, bulk deletes, and commits of secret-bearing content;
  - allows reads, edits and tests inside the project.
- **Self-protection:** the agent cannot touch the ledger, the policy, or the hook and plugin configuration.
- Repo policies are used only after you pin their hash (`policy trust`).
- `policy test` explains a decision; `policy lint` checks a policy file.

### Agents
- **Claude Code**, via hooks (`agent-ledger init`).
- **OpenCode** v1, via a plugin (`agent-ledger init --agent opencode`).

### Reports and dashboard
- `report` in Markdown, HTML or JSON: summary, riskiest events, policy versions, chain result, every event, and a control-mapping appendix (EU AI Act Art. 12/14, NIST AI RMF, ISO/IEC 42001). The appendix says "supports evidence for", never "compliant".
- `serve`: a read-only local dashboard with a session timeline, diffs and filters. It accepts GET only, binds to 127.0.0.1, checks the Host header and sends a strict CSP. `serve --demo` shows sample data.

### Verification
- More than 830 tests, including over 300 adversarial bypass cases, redaction attacks and red-team regressions.
- Three red-team passes and a `/security-review`, logged in `docs/red-team.md`.
- A real-world trial with OpenCode and a free local 8B model on django, fastify and hugo (`docs/real-world-trial.md`).
