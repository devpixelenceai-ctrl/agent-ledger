# Threat model

agent-ledger sits between an AI coding agent and its tools. This document says:
- what it protects, and against whom;
- how it does that;
- what it cannot do.

Findings from adversarial testing are in [red-team.md](red-team.md).

## Assets

1. **The user's machine and data.** This means files outside the project, credentials, and the user's other repositories.
2. **Secrets.** These are `.env` values, keys, tokens and passwords. They must not reach the log, and should not reach the agent.
3. **Shared systems.** These are git remotes (especially protected branches), package registries, production infrastructure, and databases.
4. **The integrity of the record.** The log must say what actually happened, so that a reviewer can rely on it.
5. **The user's session.** agent-ledger must never be the reason Claude Code breaks.

## Actors

| Actor | Trust | Examples |
|---|---|---|
| The user | trusted | Writes the policy, approves "ask" prompts, owns `~/.agent-ledger`. |
| The agent | **untrusted actions**, good-faith intent | It can make mistakes, follow injected instructions from a web page or README, or be over-eager ("I'll just force-push"). |
| Content the agent reads | untrusted | Web pages, issues, dependencies, a cloned repository, including its `.agent-ledger.toml` and `.claude/settings.json`. |
| Other local software running as the user | out of scope | It has the same OS permissions as agent-ledger. |

The design assumes an agent that may be **manipulated** into harmful actions, for example by prompt injection. It does not assume a fully adversarial program with independent code execution. Once the agent can run arbitrary code (for example through an approved script), that code runs with the user's permissions, and nothing at the hook layer can contain it.

## Trust boundaries and controls

```
 agent ──tool call──▶ [ Claude Code ] ──PreToolUse JSON──▶ [ agent-ledger hook ] ──▶ allow / ask / deny
                                │                                  │
                                └──PostToolUse, prompts, …─────────▶ redact ─▶ hash chain ─▶ ledger.db (0600)
```

| Threat | Control |
|---|---|
| Destructive or exfiltrating shell commands | The policy engine. Commands are normalised: quotes, escapes, `$IFS`, ANSI-C strings, braces, wrappers such as `sudo`, `env` and `xargs`, nested shells such as `bash -c` and `eval`, `find -exec`, and substitutions. Paths are resolved through `..`, `~` and symlinks. The strictest segment wins. Built-in checks cover remote code execution, force-push, `chmod 777`, writes and deletes outside the project, and pipes into interpreters. |
| Reading secrets | Path rules for `.env*`, keys and credential stores, applied to file tools and to any path an argument names (including globs expanded the way bash expands them). |
| Secrets reaching the log | Redaction in layers before anything is stored: known token formats, URL credentials, auth headers, CLI flags, `KEY=value`, high-entropy and long-hex strings, Unicode normalisation, percent-decoding, a quote-joined form of commands, and whole-content dropping for secret files. `Read` results are never stored. |
| The agent disabling or blinding agent-ledger | Self-protection rules deny access to `~/.agent-ledger/**` and writes to `.agent-ledger.toml` and `.claude/settings*.json`. `agent-ledger init` and `policy trust` require approval. `ConfigChange` events are recorded. |
| A malicious repository weakening the policy | Repo policies are ignored until their exact content hash is pinned by the user (`policy trust`). `init` never auto-trusts an existing file. Ledger settings such as `fail_mode` and `db_path` can only come from the user's config, never from a repository. |
| Tampering with the record | A SHA-256 hash chain (HMAC optional). `verify` finds edits, deletions, insertions and reordering. Session counters reveal truncation of the newest rows. `--expect-head` checks an anchored head hash. |
| Stalling the hook so it times out (Claude Code treats a timeout as **non-blocking**) | Bounded work everywhere: bounded brace expansion, single-directory globbing, a 3 s lock wait, only small regular files read from `.git`, and a nesting limit in the parser. Anything over a limit is marked unparseable, so the policy asks. |
| agent-ledger crashing the session | A catch-all wrapper. Other events always exit 0. PreToolUse follows the configured fail mode. |
| The dashboard leaking or changing data | It binds to 127.0.0.1, accepts GET only, checks the Host header (against DNS rebinding), uses a read-only SQLite connection, sends a strict CSP, makes no external requests, and inserts data with `textContent`. |

## What agent-ledger cannot stop

These limits are inherent to governing at the tool-call layer. Plan around them.

1. **Deferred execution.** The agent writes `cleanup.sh` (an allowed edit) and later runs `bash cleanup.sh`. Only the second call is checked, and only as "runs a script". Its contents are not analysed. The same applies to:
   - test runners and build tools that execute project files the agent can edit: `pytest` runs `conftest.py`, and `npm test` runs `package.json` scripts;
   - git hooks, Makefiles and similar.
   The starter policy allows tests, so a malicious agent could hide actions there.
2. **Actions outside hooked tools.** Background processes started earlier, cron jobs, editors and IDE plugins, and anything not routed through Claude Code's tool calls.
3. **Turing-complete escape hatches.** Interpreter code (`python -c`, `node -e`, `awk system()`) is detected and made to *ask*. Once approved, its behaviour is not checked. Variables computed at runtime make a command *ask*, but a person can still approve something harmful.
4. **Secrets committed by other routes.** `git add` and `git commit` scan the content being recorded, but some routes are not scanned:
   - `git stash`, `git apply --index`, `git update-index`, and other plumbing;
   - scripts that commit;
   - a secret format the detector does not recognise.
5. **Reads that do not name the file.** `grep -r KEY .` or `cat *` in a directory containing `.env` read secrets without naming them. bash's `*` skips dotfiles, but `-r` does not. The output is still redacted before logging, but the agent sees it.
6. **Encoded or fragmented secrets.** The redactor misses secrets that are deliberately disguised: ROT13, short base64 pieces, character arithmetic. It also misses secrets with no recognisable shape that sit in an unlabelled context.
7. **A writer of the database.** Anyone (or anything) running as the user can recompute the whole chain after editing it. The chain makes tampering *evident*, not impossible. Use an HMAC key stored where the agent cannot read it, and anchor head hashes (put them in reports, commits or tickets).
8. **Users and other software turning it off.** Editing `~/.claude/settings.json`, setting `disableAllHooks`, or using managed settings such as `allowManagedHooksOnly`. In an interactive session, Claude Code does not run hooks until the folder is trusted. Headless (`-p`) sessions treat every folder as trusted.
9. **The project that contains agent-ledger itself.** When agent-ledger governs its own repository (dogfooding), the agent can edit the code that governs it. A normal `pipx` install lives outside the project, where the starter policy denies writes.
10. **Fail-open gaps.** With the default `fail_mode = "open"`, an internal error, a hook timeout, or a missing `agent-ledger` binary lets the call proceed under Claude Code's normal permissions. Use `fail_mode = "closed"` and `init --fail-closed` (`onFailure: "block"`) if that is unacceptable.
11. **Outcome labels for OpenCode 1.x and Kilo.** These agents report agent-ledger's own rejection of an "ask" as a failed tool call. The ledger recognises that exact rejection for that call's rule and labels the call "not run". A command a person approved could print that exact text itself, and would then be labelled "not run" instead of "approved". This can only hide an approved action as unexecuted; it can never make a blocked action look like it ran. The full event, including the tool's output, stays in the ledger.
12. **Policy authoring mistakes.** First match wins. A broad `allow` placed above a `deny` silences the deny. `agent-ledger policy lint` warns about common cases, and `policy test` shows exactly which rule decided.

## Residual-risk guidance

- Review "ask" prompts as you would a code review. That is where the human oversight happens.
- Keep the policy in version control, but trust it only after reviewing changes. Every event records the policy hash it was decided under.
- For audits, export a report and store the head hash it prints somewhere the agent cannot write.
