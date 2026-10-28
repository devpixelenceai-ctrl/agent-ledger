# Supported agents

agent-ledger governs an agent by sitting in front of its tool calls: before a tool runs, the agent hands the call to agent-ledger, which decides with your policy and records it. All agents share one policy, one ledger, the reports and the dashboard. Only the small adapter that reads each agent's payload and answers in its format differs.

Set up any agent in a project with:

```bash
agent-ledger init --agent <name>
```

That writes the agent's own hook or plugin configuration, plus the starter policy (`.agent-ledger.toml`, trusted). Re-running it is safe: it updates only its own entries and keeps your other settings and hooks.

## Check it's working

```bash
agent-ledger doctor
```

An agent can have the hooks installed and still run ungoverned:
- Codex skips hooks you haven't approved.
- Gemini ignores project hooks outside trusted folders.
- Cline needs "Enable Hooks".
- Goose needs its plugin enabled.
- A hook that can't start fails open.

`doctor` finds every agent set up in the project and checks that the command its hook runs exists, and that the ledger has recorded events from that agent in this project. For an agent whose hooks have never fired, it tells you the agent's own fix. It also checks that the project policy is trusted, and flags hook errors logged in the last 24 hours. It exits non-zero when anything needs attention, and `--json` gives machine-readable output.

## The matrix

"Ask" is how a decision of `ask` reaches you:
- **prompt**: the agent shows its own approval prompt.
- **blocks**: the agent cannot show one, so the call is blocked and the agent is told it needs human approval. An `ask` is never allowed silently.

"Checked" says how each integration was verified:
- **live**: run end to end with the real agent and a free local model (qwen3:8b via Ollama).
- **contract**: tested against the payloads and replies documented in the agent's source or hook reference (version listed), but not run live here.

| Agent | `--agent` | Where it plugs in | Ask | Checked |
|---|---|---|---|---|
| Claude Code | `claude-code` (default) | `.claude/settings.json` hooks | prompt | live |
| OpenCode 1.x and 2.x | `opencode` | `.opencode/plugins/agent-ledger.js` | 2.x prompt, 1.x blocks | live (1.19, 2.1.4) |
| OpenAI Codex CLI | `codex` | `.codex/hooks.json` | blocks (Codex rejects `ask`) | live (0.164; after approving its hooks) |
| GitHub Copilot CLI | `copilot` | `.github/hooks/agent-ledger.json` | prompt (interactive) | contract |
| Cursor | `cursor` | `.cursor/hooks.json` | blocks (`ask` not enforced yet) | contract |
| Gemini CLI | `gemini` | `.gemini/settings.json` (trusted folders only) | prompt | contract (0.67) |
| Antigravity CLI | `antigravity` | `.agents/hooks.json` | prompt | contract |
| Cline (VS Code and CLI) | `cline` | `.clinerules/hooks/PreToolUse` and `PostToolUse`; turn on "Enable Hooks" | blocks | contract (4.1.26 / CLI 3.0.74) |
| Windsurf / Devin Desktop | `windsurf` | `.devin/hooks.json` | blocks | contract |
| Goose | `goose` | plugin `.agents/plugins/agent-ledger/`; enable it in Goose | blocks | contract (1.56) |
| Crush | `crush` | `.crush.json` (or `crush.json`) | blocks | live (0.98.2) |
| Qwen Code | `qwen` | `.qwen/settings.json` | prompt | live for reads and results (0.26.2); shell paths contract |
| Continue CLI | `continue` | `.continue/settings.json` | prompt | contract (see note) |
| Factory Droid | `factory` | `.factory/hooks.json` | prompt | contract |
| Kiro CLI | `kiro` | `.kiro/hooks/agent-ledger.json` | blocks | contract |
| Auggie CLI | `auggie` | `.augment/settings.json` plus `.augment/hooks/*.sh` | blocks (deny-only hooks) | contract |
| Devin CLI | `devin` | `.devin/hooks.v1.json` | blocks | contract |
| Kilo Code | `kilo` | `.kilo/plugins/agent-ledger.js` (OpenCode plugin API) | blocks | contract (7.8.18) |
| Amp | `amp` | `.amp/plugins/agent-ledger.ts` | prompt (`ctx.ui.confirm`) | contract |
| Anything that commits with git | `git` | `.git/hooks/pre-commit` and `pre-push` | blocks | real `git commit` in tests |

### Agents without a hook system

Aider, Warp's agent and Zed's built-in agent have no pre-tool hook today, so agent-ledger can't see or stop their individual tool calls. For them, `agent-ledger init --agent git` adds git hooks that cover what they commit and push:
- **pre-commit** blocks staged content that looks like a secret. A person can override a false positive with `git commit --no-verify`.
- **pre-push** blocks deny-level pushes, such as a force-push to `main`. Ordinary pushes are recorded, not blocked, because people push through the same hooks.

Aider skips git hooks by default. Run it with `--git-commit-verify`.

## What every integration guarantees

These hold for every agent above and are tested per agent (`tests/test_agents.py`, `tests/test_init_agents.py`, `tests/test_plugin_agents.py`):
- **Dangerous calls are blocked** in the agent's own reply format: `rm -rf ~`, reading `~/.ssh` or `.env`, `curl | sh`, writes outside the project.
- **An `ask` is never allowed silently.**
- **Harmless calls get no reply**, so the agent's own permission checks still apply.
- **Every call is recorded** under the agent's name, with the canonical tool name (`Bash`, `Read`, `Edit`, …), so reports compare agents directly.
- **Unknown tools can only make things stricter.** They keep their own name, so they need approval. Any shell command or path they carry is checked too.
- **Bad input or a crash never breaks the agent**, unless you chose fail-closed.
- **The agent can't switch agent-ledger off.** Every agent's hook and plugin configuration is protected by the starter policy.

## Notes and limits

- **Continue CLI:** the hook machinery is present, but at the source revision checked (2026-07-20) nothing called the pre-tool hook. Check that your version fires it: run `agent-ledger tail` after a tool call.
- **Codex: approve the hooks once, or Codex runs ungoverned.** Codex silently skips hooks you haven't approved; `codex exec` never asks, it just runs without them. This was found in the live run. After `init --agent codex`, start `codex` once in the project and approve the agent-ledger hooks in its review screen. agent-ledger doesn't approve them for you, because that would bypass Codex's own security review. Check it worked with `agent-ledger tail` after one tool call.
- **Codex tools:** Codex has no read or edit tools. Reads go through its shell, and edits go through `apply_patch`, whose file paths are all checked.
- **Crush 0.98.2** fires only pre-tool hooks: every call is decided and recorded, but tool results aren't recorded yet. The post-tool hook is already installed, and works once Crush releases it (it's on Crush's nightly branch).
- **Qwen Code** routes some calls through a `tool_call` bridge (`{name, args}`). Qwen resolves the bridge before running hooks, and agent-ledger also unwraps it, so the real tool is always what gets checked. Small local models often leave out the bridge's `name`, and Qwen then refuses the call itself. If you run Qwen with a small model, set `tools.toolSearch.threshold` to `100` so tools are offered directly.
- **Gemini CLI** runs project hooks only in trusted folders. Its `web_fetch` takes URLs inside a prompt, so every URL in the prompt is checked.
- **Windows:** PowerShell commands from Copilot and Kiro are checked with the POSIX shell parser. Commands that only make sense in PowerShell may need approval more often than they should.
- **Field names marked UNVERIFIED in the agent's own docs** are handled generously: several known spellings are accepted, and a tool the adapter can't read needs approval.

When an agent changes its hook format, the per-agent tests show what to update. If yours misbehaves, run it once with a hook that logs stdin and open an issue with the payload, after removing anything secret.
