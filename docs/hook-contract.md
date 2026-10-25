# Claude Code hook contract (verified)

Verified on 2026-10-26 against https://code.claude.com/docs/en/hooks.md
(`docs.claude.com/en/docs/claude-code/hooks` now redirects there), plus the
hooks guide, settings and tools-reference pages. Re-check this file when
Claude Code changes. The local CLI at the time of writing was `claude 2.1.72`.
Features marked *(v2.1.x+)* need a newer build than that.

Legend: **CONFIRMED** = the original assumption holds. **CORRECTED** = the
docs differ. **ADDED** = something the original assumption left out that
agent-ledger depends on.

## 1. Where hooks are configured

**CONFIRMED.** Hooks live in settings files:

| File | Scope |
|---|---|
| `~/.claude/settings.json` | user, all projects |
| `.claude/settings.json` | project, committed |
| `.claude/settings.local.json` | project, personal, not committed |

Managed policy settings, plugin `hooks/hooks.json`, and skill or subagent
frontmatter can also define hooks.

Shape: event → list of matcher groups → list of handlers.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "agent-ledger hook", "timeout": 10 }
        ]
      }
    ]
  }
}
```

Useful handler fields: `type` (`command`, `http`, `mcp_tool`, `prompt`,
`agent`), `command`, `timeout` (seconds), `if`, `statusMessage`, `async`,
`shell`, and `onFailure` (`"continue"` by default, or `"block"`)
*(v2.1.295+)*.

### Matchers: CORRECTED

A matcher is not always a regex:

- `"*"`, `""` or no matcher matches everything.
- A value made only of letters, digits, `_`, `-`, spaces, `,` and `|` is an
  exact name or a list: `"Bash"`, `"Edit|Write"`, `"Edit, Write"`.
- Any other character turns it into an **unanchored** JavaScript regex, for
  example `mcp__.*` or `^Notebook`.
- Matchers are case-sensitive.

Events that take a matcher, and what the matcher filters:

| Event(s) | Filters on |
|---|---|
| tool events: PreToolUse, PostToolUse, PostToolUseFailure, PermissionRequest, PermissionDenied | tool name |
| SessionStart | `startup`, `resume`, `clear`, `compact`, `fork` |
| SessionEnd | `clear`, `resume`, `logout`, `prompt_input_exit`, `other` |
| PreCompact, PostCompact | `manual`, `auto` |
| SubagentStart, SubagentStop | agent type |
| Notification | notification type |
| ConfigChange | `user_settings`, `project_settings`, `local_settings`, `policy_settings`, `skills` |

UserPromptSubmit and Stop ignore the matcher, along with several other
events.

MCP tools are named `mcp__<server>__<tool>`. Plugin-bundled servers are named
`mcp__plugin_<plugin>_<server>__<tool>`.

## 2. Events: CORRECTED (the original list was a subset)

The reference lists 33 events. agent-ledger uses these:

| Event | Why agent-ledger needs it | Can it block? |
|---|---|---|
| SessionStart | session metadata (cwd, git, model) | no (exit 2 only shows stderr) |
| UserPromptSubmit | records the prompt | yes |
| PreToolUse | **policy decision** | yes |
| PermissionRequest | shows that the user saw a prompt | decides with `decision.behavior`; ignores exit 2 |
| PermissionDenied | the user or a classifier denied the call | n/a |
| PostToolUse | outcome, diff, and proof that an "ask" was approved | feedback only |
| PostToolUseFailure | failed tool calls | feedback only |
| Stop, SubagentStart, SubagentStop | timeline | Stop and SubagentStop can |
| SessionEnd | end time and reason | no, and all hooks share a **1.5 s budget** |
| ConfigChange | detects settings edits, such as someone removing our hook | yes |

The other events (Notification, PreCompact, CwdChanged, FileChanged, …) are
recorded generically if they are configured.

## 3. Stdin JSON

**CONFIRMED** common fields: `session_id`, `transcript_path`, `cwd`,
`hook_event_name`.

**ADDED** common fields: `permission_mode` (`default`, `plan`,
`acceptEdits`, `auto`, `dontAsk`, `bypassPermissions`), `prompt_id`,
`effort`, and in subagents `agent_id` and `agent_type`.

Per event:

| Event | Fields |
|---|---|
| PreToolUse | `tool_name`, `tool_input`, `tool_use_id`; MCP tools also get `mcp_server: {name, source}` *(v2.1.274+)* |
| PostToolUse | `tool_name`, `tool_input`, `tool_response` (shape depends on the tool), `tool_use_id`, `duration_ms` |
| PostToolUseFailure | `tool_name`, `tool_input`, `tool_use_id`, `error`, `is_interrupt`, `duration_ms` |
| PermissionRequest | `tool_name`, `tool_input`, `permission_suggestions` (no `tool_use_id`) |
| UserPromptSubmit | `prompt` (pasted text arrives expanded), optional `session_title` |
| SessionStart | `source`, and optionally `model`, `agent_type`, `session_title` |
| SessionEnd | `reason` |
| Stop | `stop_hook_active`, `last_assistant_message` |
| SubagentStart | `agent_id`, `agent_type` |
| Notification | `message`, `title`, `notification_type` |

**ADDED.** File-tool paths (`Read`, `Write`, `Edit`) are always absolute:
Claude Code expands `~` and relative paths first. On Windows they use
backslashes. Bash commands are **not** normalised, so we must do it.

## 4. PreToolUse output: CONFIRMED, with additions

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "agent-ledger: rule secrets.env-read: reading .env files is blocked"
  }
}
```

| Decision | Effect | Who sees the reason |
|---|---|---|
| `allow` | skips the prompt; **does not** override settings deny or ask rules | nobody (debug log only) |
| `deny` | cancels the call in **every** permission mode, including `bypassPermissions` | Claude |
| `ask` | forces Claude Code's normal approval prompt, even in auto mode | the user, in the prompt |
| `defer` | `-p` mode only; pauses for an SDK wrapper | debug log |

When several hooks respond, the precedence is `deny` > `defer` > `ask` >
`allow`. Every matching hook runs, in parallel.

**ADDED.** Two more output fields exist: `updatedInput`, which replaces the
whole input, and `additionalContext`. agent-ledger uses neither in v1.

The top-level `decision` and `reason` fields are deprecated for PreToolUse.

**Design choice.** agent-ledger returns `allow` only when the policy
explicitly says so. "No opinion" means exit 0 with no output, so Claude
Code's own permission flow runs as normal. Because allow does not override
settings deny rules, our allows can't weaken the user's settings.

## 5. Exit codes: mostly CONFIRMED, one correction

- **Exit 0.** Stdout is parsed as JSON only if it is exactly one JSON object
  with nothing but whitespace around it.
- **CORRECTED.** A valid JSON object is applied on **any** exit code, and the
  exit code is then ignored. Rule: on the JSON path, print JSON and exit 0. On
  the error path, print nothing to stdout.
- **Exit 2** is a blocking error on PreToolUse, UserPromptSubmit, Stop,
  SubagentStop, ConfigChange, PreCompact and some others. Stderr goes to
  Claude. On SessionStart, SessionEnd and PostToolUse it only shows stderr.
- **Any other non-zero exit**, a crash, a timeout, or "command not found" is
  a **non-blocking** error: the tool call goes ahead and a "hook error"
  notice appears. The only exception is a handler with `onFailure: "block"`
  *(v2.1.295+)*.

Consequences for agent-ledger's fail modes:

| Mode | Internal error in PreToolUse | Notes |
|---|---|---|
| `fail_open` (default) | exit 0, no stdout, error logged | normal Claude Code permissions apply |
| `fail_closed` | exit 2, short message on stderr | Claude sees why. All other events still exit 0, so the session never breaks. |

Neither mode can catch a hook that never starts (binary missing, wrong
path) or a timeout. On v2.1.295+, `init --fail-closed` also sets
`onFailure: "block"` on the PreToolUse handler to cover that case.

## 6. Timeouts, concurrency, environment

- The default timeout is **600 s** for `command` hooks, 30 s for
  UserPromptSubmit, and a shared **1.5 s** for SessionEnd. agent-ledger sets
  `timeout: 10` explicitly.
- Matching hooks run **in parallel**, and several sessions can run at once.
  The ledger has to cope with concurrent writers: SQLite WAL mode plus
  `BEGIN IMMEDIATE` around the "read chain head, then insert" step.
- Environment: `CLAUDE_PROJECT_DIR` (project root; use it to decide what
  counts as "inside the project"), `CLAUDE_PLUGIN_ROOT`, `CLAUDE_ENV_FILE`
  and others.
- Common output fields: `continue`, `stopReason`, `systemMessage` (a warning
  shown to the user), `suppressOutput`. Text output is capped at 10,000
  characters.

## 7. Built-in tool input shapes (tools reference)

| Tool | `tool_input` fields |
|---|---|
| Bash | `command`, `description`, `timeout`, `run_in_background` |
| Edit | `file_path`, `old_string`, `new_string`, `replace_all` |
| Write | `file_path`, `content` |
| Read | `file_path`, `offset`, `limit` |
| Glob | `pattern`, `path` |
| Grep | `pattern`, `path`, `glob`, `output_mode`, … |
| WebFetch | `url`, `prompt` |
| WebSearch | `query`, `allowed_domains`, `blocked_domains` |
| Agent | `prompt`, `description`, `subagent_type`, `model` |

MultiEdit and NotebookEdit are not documented here. agent-ledger handles any
tool with `file_path` or `notebook_path` keys, and any `edits[]` array, in a
generic way, so it does not depend on these tools having a fixed shape.

## 8. Permissions, reloading and trust

- **CONFIRMED.** A hook's `deny` holds in every mode, and a hook's `ask`
  forces a prompt.
- **CORRECTED.** Hooks are not fixed at session start. Claude Code watches
  the settings files and reloads hook edits; restart only if an edit doesn't
  show up. `/hooks` is a read-only browser, not an approval step.
- **ADDED: workspace trust.** In an interactive session, hooks from any
  settings file are held back until the user accepts the folder-trust dialog.
  In `-p` and SDK sessions the folder is treated as trusted.
- **ADDED: these settings switch hooks off.** `"disableAllHooks": true` and
  `allowManagedHooksOnly` both stop our hook from running. agent-ledger must
  protect the settings files (policy rule and ConfigChange recording), and
  the threat model must say that someone with settings access can turn it
  off.
