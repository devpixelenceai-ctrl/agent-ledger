# Policy reference

## Where policies come from

The hook loads exactly one policy, in this order:

1. `<project>/.agent-ledger.toml`, **only if trusted**: its SHA-256 must match the hash pinned by `agent-ledger policy trust` (or written by `agent-ledger init`). Any change to the file un-trusts it until you run `policy trust` again.
2. `~/.agent-ledger/policy.toml`, the user policy, which is always trusted.
3. The built-in starter policy, `agent_ledger/policies/starter.toml`.

A missing, untrusted or invalid file falls through to the next one. The reason is logged to `~/.agent-ledger/errors.log` and shown once at session start. To see which policy is in force, run `agent-ledger policy show`.

Every event stores the hash of the selected policy file, and the audit report lists each policy version that was in force.

## File structure

```toml
[settings]
default_decision = "ask"                 # allow | ask | deny, for anything no rule matches
allowed_domains = ["github.com", "pypi.org"]   # used by domains = "allowlisted" / "not_allowlisted"
max_delete_files = 10                    # used by check = "too_many_deletes"
protected_branches = ["main", "master"]  # used by check = "git_force_push_protected"
temp_dirs = ["/tmp", "/private/tmp", "/var/folders"]  # writable like the project; $TMPDIR and the
                                                      # session's scratchpad dir are always added

[[rule]]
id = "unique.id"            # required
description = "..."         # shown by `policy test` and used as the default reason
decision = "deny"           # required: allow | ask | deny
severity = "critical"       # info | low | medium | high | critical (default: allow=info, ask=medium, deny=high)
reason = "..."              # deny: shown to the agent; ask: shown to the user in the approval prompt
# ...conditions...
```

Unknown keys are errors, so typos cannot silently disable a rule.

## Conditions

All conditions in a rule must match (AND). If a list is given for one condition, any item can match (OR).

| Key | Matches when |
|---|---|
| `tools` | The tool name is one of the given names. You can use globs (`mcp__*`) or a regex with a `re:` prefix (`re:^Notebook`). If omitted, the rule applies to any tool. Shell commands use `Bash`. |
| `commands` | (shell) The command name after normalisation is one of these (globs allowed): `rm`, `git`, `python*`. |
| `command` | (shell) A regex `re.search` on the normalised simple command, for example `git push --force origin main`. For other tools it searches the file path or URL. |
| `paths` | Any path the unit touches matches one of the globs (see below). |
| `exclude_paths` | These paths are ignored when checking `paths`. |
| `access` | Which paths `paths` looks at: `read`, `write` (includes deletes), `delete`, or `any` (the default). |
| `within_project` | `true`: every path is inside the project, a temp dir, or `/dev/null` and similar, and nothing is computed at runtime. `false`: the opposite. |
| `domains` | `"allowlisted"`: every host is allowed. `"not_allowlisted"`: some host is not. A list: some host is in the list (subdomains match). |
| `mcp_source` | The MCP server's `source` (`sdk`, `user`, `project`, `plugin`, …) is one of these. |
| `check` | A built-in predicate (see below). |

### Paths and globs

- `**/` matches any directories, `*` any characters within one path segment, `?` one character, and `[abc]` a character class. Matching is case-insensitive.
- A pattern with no `/` (like `*.pem`) matches a file name anywhere.
- Placeholders: `{project}` is the project root, `{ledger_home}` is `~/.agent-ledger` (or `$AGENT_LEDGER_HOME`), and `~` is `$HOME`.
- Paths are resolved before matching: relative to the effective working directory (including `cd` earlier in the same command), with `..`, `~`, `$HOME` and symlinks resolved.
- A glob argument such as `cat .e*` is expanded within its directory the way bash would. A wildcard in a directory component (`*/.env`) is instead checked against a list of sensitive file names.

For shell commands, a path is any argument that is not an option, any `--opt=value` value, any literal variable assignment, and any redirect target. A few arguments are treated as **text, not paths**:
- `echo` and `printf` arguments;
- git commit, tag and grep messages and patterns;
- the first pattern argument of `grep`, `rg`, `sed`, `awk` and `jq`.

So `git commit -m "ignore .env"` does not count as reading `.env`.

Some commands have known write and delete targets: `rm`, `mv`, `cp`, `tee`, `touch`, `mkdir`, `chmod`, `dd of=`, `sed -i`, `curl -o`, `wget -O`, `tar -C`, `git clone`, `find -delete`, and redirects such as `>`.

### Built-in checks

| Check | Level | True when |
|---|---|---|
| `remote_pipe_to_shell` | command | Downloaded content reaches a shell or interpreter. Examples: `curl … \| sh`, `wget -O- … \| sudo bash`, `bash <(curl …)`, `sh -c "$(curl …)"`, `eval "$(curl …)"`, `source <(curl …)`. |
| `pipe_to_shell` | command | Any data is piped into a shell or interpreter reading stdin, for example `base64 -d \| sh`. |
| `unparseable` | command | The parser gave up: unbalanced quotes, nesting deeper than 8 levels, a brace expansion that is too large, or a command over 200 KB. |
| `delete_outside_project` | segment | A delete targets something outside the project, or the project root itself. |
| `write_outside_project` | segment | A write targets something outside the project and outside the temp dirs. |
| `unknown_write_target` | segment | A write or delete target is computed at runtime. |
| `too_many_deletes` | segment | The delete is recursive or uses a glob, `xargs`/`find -exec` supplies the targets, or it names more than `max_delete_files` files. |
| `git_force_push_protected` | segment | A force push (`-f`, `--force*`, `+refspec`, `--mirror`) or a delete (`--delete`, `:branch`) targets a protected branch. If no refspec is given, this applies when the current branch is protected or unknown. |
| `chmod_world_writable` | segment | `chmod` grants write permission to others (`777`, `666`, `o+w`, `a+rwx`). |
| `dynamic_command` | segment | The program name comes from a variable or substitution. |
| `inline_code` | segment | Interpreter code is given inline: `python -c`, `node -e`, `perl -e`, a here-doc into `python`, or `awk` with `system()`. |
| `runs_script` | segment | A shell or interpreter runs a script file. |
| `git_config_override` | segment | `git -c …`, which can run programs through aliases or `core.sshCommand`. |

Command-level checks can only be combined with `tools` and `command`.

## How a decision is made

1. The tool call becomes **units**:
   - A non-shell tool is one unit.
   - A shell command becomes one unit per simple command, including those inside `bash -c`, `$(…)`, here-docs, `find -exec` and similar. It also gets one command-level unit for pipeline checks.
2. Each unit takes the **first** rule that matches it. A segment unit that matches no rule gets `default_decision`. A command-level unit with no match has no opinion.
3. The tool call's decision is the **strictest** unit decision: `deny` > `ask` > `allow`.

Keep **deny rules first**, then ask, then allow. `agent-ledger policy lint` warns when a broad allow comes before a deny.

## Testing a policy

```bash
agent-ledger policy test "cd build && rm -rf ../*"
agent-ledger policy test ~/.ssh/id_rsa --tool Read
agent-ledger policy test https://example.com --tool WebFetch
agent-ledger policy test "x" --tool Write --input '{"file_path": "/etc/hosts", "content": "x"}'
agent-ledger policy lint .agent-ledger.toml
agent-ledger policy trust            # after reviewing changes to .agent-ledger.toml
```

`policy test` prints every unit, the rule that decided it, and the final decision and reason.

## Examples

Allow a specific internal domain for `WebFetch`:

```toml
[settings]
allowed_domains = ["github.com", "docs.internal.example.com"]
```

Block Docker entirely:

```toml
[[rule]]
id = "no-docker"
tools = ["Bash"]
commands = ["docker", "podman"]
decision = "deny"
reason = "containers are not allowed in this repo"
```

Allow one trusted MCP server without prompting (place it above `mcp.default`):

```toml
[[rule]]
id = "mcp.linear"
tools = ["mcp__linear__*"]
decision = "allow"
```
