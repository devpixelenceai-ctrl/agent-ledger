# agent-ledger

**A flight recorder and seatbelt for AI coding agents.** agent-ledger does three things:
- It records every action an agent takes, in a tamper-evident local log.
- It stops risky actions until a person approves them.
- It turns the record into an audit report you can hand to security or compliance.

It is free and runs entirely on your machine: no accounts, no cloud, and no dependencies beyond the Python standard library. The first integration is [Claude Code hooks](docs/hook-contract.md). The core is agent-agnostic, so other agents can plug in later.

![Demo: a blocked `curl | sh` in Claude Code](docs/img/demo-block.gif)
<!-- GIF placeholder: record with `agent-ledger serve --demo` and a live Claude Code session -->

## Why

Agents now run shell commands, edit code and push to remotes on their own. The tooling to govern them has not kept up:

- Only **1 in 5 companies** has a mature governance model for autonomous agents (Deloitte, *State of AI in the Enterprise*, 2026).
- Gartner expects **over 40% of agentic AI projects to be cancelled by 2027**, in part because of inadequate risk controls.

Teams lack three things:
1. A trustworthy record of what the agent did.
2. Rules that block dangerous actions *before* they happen.
3. A report they can hand to someone who has to sign off.

agent-ledger provides all three.

## 60-second quickstart

You need Python 3.11+ and [pipx](https://pipx.pypa.io).

```bash
pipx install git+https://github.com/<you>/agent-ledger   # or, from a checkout: pipx install .
cd your-project
agent-ledger init        # adds hooks to .claude/settings.json, writes and trusts .agent-ledger.toml
claude                   # use Claude Code as usual: every action is now logged and governed
```

Then look at what happened:

```bash
agent-ledger tail                       # latest events
agent-ledger sessions                   # one line per session
agent-ledger serve                      # read-only dashboard on http://127.0.0.1:8765
agent-ledger report --since 7d --format html -o audit.html
agent-ledger verify                     # check the hash chain
```

To try the dashboard without running an agent, use `agent-ledger serve --demo`.

![Dashboard: session barcode and timeline](docs/img/dashboard.gif)
<!-- GIF placeholder -->

## Supported agents

| Agent | How agent-ledger plugs in | Set up with |
|---|---|---|
| **Claude Code** | Hooks in `.claude/settings.json` | `agent-ledger init` |
| **OpenCode** (v1.x) | A plugin in `.opencode/plugins/` | `agent-ledger init --agent opencode` |

Both agents share the same policy, ledger, reports and dashboard.

OpenCode's v1 plugin API cannot show an approval prompt, so under OpenCode an "ask" blocks the call. The agent is told the call needs human approval.

agent-ledger has been tested on real work with OpenCode and a free local 8B model (qwen3:8b via Ollama) on django, fastify and hugo:
- every tool call was recorded;
- no secrets leaked;
- no hook crashed.

See [docs/real-world-trial.md](docs/real-world-trial.md).

## What you get

| | |
|---|---|
| **Recorder** | Every hook event (prompts, tool calls, decisions, results, session start and end) lands in SQLite at `~/.agent-ledger/ledger.db`. Each row stores `sha256(previous hash + row)`, so editing, deleting or reordering rows breaks the chain, and `verify` names the first broken row. Secrets are redacted before anything is written. |
| **Policy gate** | A TOML policy decides `allow`, `ask` (Claude Code shows its approval prompt) or `deny` (the call is blocked and the agent is told why), before each tool call. Shell commands are normalised first, so `bash -c '…'`, `sudo`, quoting tricks, `$IFS`, `eval`, `find -exec` and similar can't sneak past. |
| **Audit report** | Markdown, HTML or JSON. It contains a summary, the riskiest events, every event, the policy version in force, the hash-chain result, and an appendix mapping the evidence to EU AI Act Articles 12 and 14, the NIST AI RMF, and ISO/IEC 42001. |
| **Dashboard** | A local, read-only page: sessions, a per-session "barcode" of decisions, a timeline with diffs, and filters. |

The starter policy, briefly:
- **Denied:**
  - `rm -rf` outside the project;
  - reading or editing `.env*`, keys and credential files;
  - `curl … | sh` and similar;
  - force-pushing to `main` or `master`;
  - `chmod 777`;
  - writing outside the project;
  - touching agent-ledger's own log, policy or hook settings.
- **Asks first:**
  - `git push`;
  - package installs;
  - migrations;
  - `terraform apply`, `kubectl` and deploys;
  - network access to domains not on the allowlist;
  - bulk deletes;
  - third-party MCP tools.
- **Allowed:** reads, searches, tests, and edits inside the project.

## The policy format

```toml
[settings]
default_decision = "ask"            # for anything no rule matches
allowed_domains = ["github.com", "pypi.org"]

[[rule]]
id = "secrets.files"
description = "Reading or editing secrets files"
paths = ["**/.env", "**/.env.*", "**/*.pem", "**/id_rsa*"]
exclude_paths = ["**/.env.example"]
decision = "deny"
severity = "critical"
reason = "secrets files are off-limits; ask a human to provide what you need"

[[rule]]
id = "git.push"
tools = ["Bash"]
command = '^git push\b'
decision = "ask"
```

How rules are applied:
- The first matching rule wins.
- A shell command is split into its simple commands. Each one is judged on its own, and the strictest result wins (deny > ask > allow), so `pytest && rm -rf ~` is denied.

Tools for writing and checking rules:
- `agent-ledger policy test "<command>"` shows which rule matched and why.
- `agent-ledger policy lint` catches mistakes.

The full reference is in [docs/policy-reference.md](docs/policy-reference.md).

**Repo policies must be trusted.** A cloned repository could ship a permissive `.agent-ledger.toml`. The hook only uses a repo policy whose hash you have pinned with `agent-ledger policy trust`. Otherwise it falls back to `~/.agent-ledger/policy.toml` or the built-in starter policy, and warns you at session start.

## Configuration

Settings that must not be controlled by a repository live in `~/.agent-ledger/config.toml`:

```toml
[ledger]
fail_mode = "open"          # or "closed", see below
db_path = "~/.agent-ledger/ledger.db"
hmac_key_file = "~/.config/agent-ledger.key"   # optional: HMAC rows with a key the agent cannot read
max_field_chars = 65536
```

You can also use these environment variables: `AGENT_LEDGER_HOME`, `AGENT_LEDGER_DB`, `AGENT_LEDGER_FAIL_MODE` and `AGENT_LEDGER_HMAC_KEY`.

**Fail open or fail closed?** agent-ledger never crashes your session. If it hits an internal error, it logs it to `~/.agent-ledger/errors.log` and then:

- **`open` (default):** it gets out of the way. Claude Code's normal permission rules still apply. The risk is that a bug or a broken install silently stops enforcement for that call. The error is logged and the event is still recorded where possible.
- **`closed`:** it blocks the tool call (exit code 2) and the agent sees why. This is safer, but a broken install stops all tool use until you fix it. `agent-ledger init --fail-closed` also sets Claude Code's `onFailure: "block"` (Claude Code 2.1.295+), so the call is blocked even when the hook cannot start at all.

Choose closed for unattended or high-stakes agents. Choose open for interactive day-to-day work.

## What agent-ledger cannot do

Be clear-eyed about these. They are covered in depth in [docs/threat-model.md](docs/threat-model.md).

- **It sees tool calls, not intentions.** If an agent writes a script now and runs it later, only the call that runs the script is checked, not what the script does. The same applies to `npm test` running a test file the agent just edited.
- **It only governs hooked tools.** Anything the agent does outside Claude Code's tools is invisible: code that runs at build time, a git hook it installed, a process it left running.
- **Shell analysis is static.** It sees through quoting, wrappers, nested shells and simple variables. Anything computed at runtime makes it *ask*, not allow.
- **Redaction is pattern-based.** A secret deliberately disguised (ROT13, split into short pieces) can get past it.
- **The hash chain is tamper-evident, not tamper-proof.** Someone who can write the database can rewrite the whole chain. To defend against that, anchor the head hash (`verify --expect-head`) or use an HMAC key the agent cannot read.
- **Anyone who can edit `~/.claude/settings.json` can turn it off.** The starter policy stops the *agent* from doing that, but not you, and not other software running as you.
- **The control mapping supports evidence for compliance work. It is not a compliance certificate.**

## Performance

The hook runs before every tool call, so it is kept lean:
- standard library only, with lazy imports;
- git information is read from `.git` files directly, with no subprocess;
- parsed policies are cached as JSON.

`tests/test_benchmark.py` spawns the real hook against a ledger of 3,000+ events and asserts **p95 < 50 ms**. It also samples a bare Python interpreter alongside, so you can see whose time it is.

Measured on an Apple Silicon laptop:

| Conditions | Hook p95 | Interpreter alone | agent-ledger's share |
|---|---|---|---|
| Idle | 32–41 ms (dev venv and pipx install) | ~18 ms | ~14–20 ms |
| Under load | 55–80 ms | 33–45 ms | 15–40 ms |

The 50 ms budget holds on an idle machine. Under load, Python start-up alone can consume most of it. That is the cost of a Python, standard-library-only hook.

CI runs the benchmark in report-only mode, because shared runners make wall-clock budgets meaningless. The deterministic guard that *is* enforced in CI is a test that fails if anything heavy is imported on the hook's hot path.

## Troubleshooting

- **`agent-ledger: command not found` or no events logged.** pipx installs into `~/.local/bin`, which may not be on your `PATH`. `agent-ledger init` notices this and writes the full path into the hook command, but `pipx ensurepath` fixes it for your shell too. A hook that cannot start is treated by Claude Code as a non-blocking error, so the session runs **ungoverned**. Check for a "hook error" notice, or run `agent-ledger tail` after a tool call.
- **Hooks feel slow (more than 50 ms).** Python start-up dominates, and it is much slower if the interpreter's standard library was never byte-compiled. A freshly installed Homebrew Python, combined with `PYTHONDONTWRITEBYTECODE=1`, can add about 40 ms per call. Install on an interpreter you already use (`pipx install --python python3.12 .`), or byte-compile its standard library once.

## Development

```bash
python3.11 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest            # 540+ tests, including policy bypass, redaction, red-team and latency suites
```

Related documents:
- [docs/hook-contract.md](docs/hook-contract.md): the verified Claude Code hook contract.
- [docs/threat-model.md](docs/threat-model.md): what is defended and what isn't.
- [docs/red-team.md](docs/red-team.md): findings from adversarial passes and their regression tests.

This repository governs its own development: `.claude/settings.json` runs agent-ledger on every tool call made while building it.

## License

MIT
