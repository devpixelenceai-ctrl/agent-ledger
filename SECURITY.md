# Security policy

agent-ledger is a security tool, so bypasses of its policy engine, its redaction or its hash chain are the bugs that matter most. Thank you for looking.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through GitHub instead:
**Security → Report a vulnerability** on this repository.

Include:
- the agent (Claude Code or OpenCode) and the agent-ledger version or commit;
- the exact tool call, command or input;
- the decision you got, and the decision you expected;
- any policy changes from the starter policy.

You should get an acknowledgement within a few days. Confirmed issues are fixed with a regression test, logged in [docs/red-team.md](docs/red-team.md), and credited if you want credit.

## What counts

In scope:
- **A dangerous action allowed (or only asked).** Examples: `rm -rf` outside the project, reading `.env` or keys, `curl | sh`, a force-push to main, writes outside the project, or tampering with agent-ledger's own files, policy or hooks.
- **A secret reaching the ledger, a report or the dashboard unredacted.**
- **A hash-chain change that `agent-ledger verify` does not detect.**
- **Code execution triggered inside the hook by untrusted content** (for example, a cloned repo's git config).
- **The dashboard writing to the ledger, or being reachable from another origin.**
- **A crash, hang or timeout that makes the hook fail open.**

Known limits that are out of scope are listed in [docs/threat-model.md](docs/threat-model.md). For example: a script the agent wrote and later ran, actions outside hooked tools, or deliberately encoded secrets. Ideas for narrowing those limits are still welcome as regular issues.
