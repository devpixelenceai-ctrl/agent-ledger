"""Shared pieces for governing any coding agent.

Most agents now expose a pre-tool hook that sends the tool name and its arguments as JSON. They
differ in tool names ("run_shell_command", "execute_command", "launch-process"), argument names
("absolute_path", "old_str", "cmd") and the reply they expect. This module handles both halves:

- `infer_action` maps any agent's tool call onto the canonical tools the policy understands. Only a
  known tool name is mapped. An unknown tool keeps its own name, "<agent>:<tool>", so no rule that
  allows built-in tools can allow it, and it needs approval by default. Any shell command or path it
  carries is still normalised, and the policy checks those too: unknown tools can only be stricter.
- `render_decision` writes a decision in one of the reply styles agents use. Where an agent cannot
  show an approval prompt, "ask" becomes a block that says the call needs human approval: a call
  that needs approval is never allowed by default.

Per-agent profiles (adapters/agents.py) pick the payload fields, tool table and reply style.
"""

from __future__ import annotations

import json
import shlex

from agent_ledger.adapters.opencode import _abs, _patch_input
from agent_ledger.model import Decision

# argument aliases -> canonical argument name
_PATH_KEYS = ("file_path", "filePath", "absolute_path", "path", "target_file", "filename", "file", "notebook_path")
_DIR_KEYS = ("path", "dir_path", "directory", "dir", "target_directory", "absolute_path")
_RENAME = {
    "old_str": "old_string", "oldString": "old_string", "old_text": "old_string",
    "new_str": "new_string", "newString": "new_string", "new_text": "new_string",
    "file_content": "content", "contents": "content", "file_text": "content",
}
_COMMAND_KEYS = ("command", "cmd", "command_line", "commandLine", "script")
_CONTENT_KEYS = ("content", "contents", "file_content", "file_text", "text")
_SHELLS = ("bash", "sh", "zsh", "dash", "/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/bash")

# lower-cased tool name with "-" as "_" -> canonical tool
_NAMES = {
    "Bash": ("bash", "shell", "run_shell_command", "execute_command", "execute_bash", "launch_process",
             "run_terminal_cmd", "run_terminal_command", "execute", "run_command", "run_commands", "exec_command",
             "local_shell", "shell_command", "terminal", "run_in_terminal", "developer__shell", "exec"),
    "Read": ("read", "read_file", "view", "view_file", "fs_read", "read_many_files", "open_file", "cat_file"),
    "Write": ("write", "write_file", "write_to_file", "save_file", "create", "create_file", "fs_write", "new_file"),
    "Edit": ("edit", "edit_file", "replace", "str_replace", "str_replace_editor", "replace_in_file", "multi_edit",
             "multiedit", "search_replace", "apply_diff", "insert_edit_into_file", "insert"),
    "ApplyPatch": ("apply_patch", "patch"),
    "WebFetch": ("webfetch", "web_fetch", "fetch", "fetchurl", "fetch_url", "url_fetch", "read_web_page"),
    "WebSearch": ("websearch", "web_search", "google_web_search", "search_web"),
    "Grep": ("grep", "grep_search", "search_file_content", "search_files", "ripgrep", "search"),
    "Glob": ("glob", "file_search", "find_files", "find_by_name"),
    "LS": ("ls", "list", "list_directory", "list_dir", "list_files", "fs_list"),
    "TodoWrite": ("todowrite", "todo_write", "write_todos", "update_plan", "update_todo_list"),
    "Task": ("task", "subagent", "spawn_agent", "new_task"),
    "AskUserQuestion": ("ask_followup_question", "ask_user", "question"),
}
_BY_NAME = {alias: tool for tool, aliases in _NAMES.items() for alias in aliases}


def _norm(name: str) -> str:
    return name.strip().lower().replace("-", "_").replace(" ", "_")


def _first_str(args: dict, keys) -> str | None:
    for k in keys:
        if isinstance(args.get(k), str) and args[k]:
            return args[k]
    return None


def _command(args: dict) -> str | None:
    """The shell command a tool call runs. Lists are argv (Codex: ["bash", "-lc", "ls"])."""
    if isinstance(args.get("commands"), list):
        parts = []
        for c in args["commands"]:
            if isinstance(c, str):
                parts.append(c)
            elif isinstance(c, dict) and isinstance(c.get("command"), str):  # Cline: {command, args[]}
                extra = c.get("args") if isinstance(c.get("args"), list) else []
                parts.append(shlex.join([c["command"], *[str(a) for a in extra]]) if extra else c["command"])
        return " && ".join(parts) if parts else None
    for k in _COMMAND_KEYS:
        v = args.get(k)
        if isinstance(v, str) and v:
            return v
        if isinstance(v, list) and v and all(isinstance(x, str) for x in v):
            if len(v) >= 3 and v[0] in _SHELLS and v[1] in ("-c", "-lc", "-ic", "-ilc"):
                return v[2]
            return shlex.join(v)
    return None


def _renamed(args: dict, path_key: str | None) -> dict:
    out = {}
    for k, v in args.items():
        if path_key and k in _PATH_KEYS and k != "file_path":
            if "file_path" not in args and "file_path" not in out:
                out["file_path"] = v
            continue
        out[_RENAME.get(k, k)] = v
    return out


def _file(tool: str, args: dict, cwd: str | None) -> tuple[str, dict]:
    if tool == "Read" and isinstance(args.get("paths"), list):
        paths = [_abs(p, cwd) for p in args["paths"] if isinstance(p, str)]
        return "Read", {"file_paths": paths, **({"file_path": paths[0]} if paths else {})}
    ti = _renamed(args, "file_path")
    if isinstance(ti.get("file_path"), str):
        ti["file_path"] = _abs(ti["file_path"], cwd)
    if tool == "Read":
        ti = {k: v for k, v in ti.items() if k in ("file_path", "offset", "limit")}
    return tool, ti


def _dir(tool: str, args: dict, cwd: str | None) -> tuple[str, dict]:
    ti = {}
    for k, v in args.items():
        if k in _DIR_KEYS:
            if "path" not in ti and isinstance(v, str):
                ti["path"] = _abs(v, cwd)
        elif k in ("regex", "query") and tool == "Grep" and "pattern" not in args:
            ti["pattern"] = v
        elif k in ("include", "file_pattern", "includePattern") and tool == "Grep":
            ti["glob"] = v
        else:
            ti[k] = v
    return tool, ti


def infer_action(name: str, args, cwd: str | None = None, agent: str | None = None,
                 names: dict | None = None) -> tuple[str, dict]:
    """(canonical tool, canonical tool_input) for one tool call from any agent.

    `names` is a profile's own table (exact tool name -> canonical tool), checked first."""
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            args = {"input": args}
    if not isinstance(args, dict):
        args = {"input": args}
    name = str(name or "")
    if name.startswith("mcp__"):
        return name, dict(args)
    tool = (names or {}).get(name) or _BY_NAME.get(_norm(name))

    if tool == "Bash":
        cmd = _command(args)
        if cmd is None:  # a shell tool without a recognisable command: check it as an empty command
            cmd = _first_str(args, ("input",)) or ""
        return "Bash", {"command": cmd}
    if tool == "ApplyPatch":
        text = _first_str(args, ("input", "patch", "patchText", "patch_text", "diff"))
        return "ApplyPatch", _patch_input({"patchText": text or ""}, cwd)
    if tool in ("Read", "Write", "Edit"):
        return _file(tool, args, cwd)
    if tool in ("Grep", "Glob", "LS"):
        return _dir(tool, args, cwd)
    if tool == "WebFetch":
        url = _first_str(args, ("url", "uri", "href"))
        return "WebFetch", {"url": url or ""}
    if tool is not None:
        return tool, dict(args)
    # unknown: keep it distinct from built-in tools so no allow rule matches it. The policy also checks
    # any command it carries as shell and any path it names as a possible write (stricter only).
    ti = dict(args)
    cmd = _command(args)
    if cmd is not None:
        ti["command"] = cmd
    path = _first_str(args, _PATH_KEYS)
    if path and "file_path" not in ti:
        ti["file_path"] = _abs(path, cwd)
    return f"{agent or 'agent'}:{name}", ti


# ---------------------------------------------------------------- replies

NEEDS_APPROVAL = " - this needs human approval, and this agent cannot ask for it here, so it was blocked."


def _reason(d: Decision) -> str:
    return f"agent-ledger [{d.rule_id}]: {d.reason or d.rule_id}"


def render_decision(decision: Decision | None, style: str, ask_supported: bool) -> tuple[str, int]:
    """(text, exit code) for a pre-tool decision. Exit code 2 means "block; text goes to stderr".

    "allow" produces no output, so the agent's own permission checks still apply."""
    if decision is None or decision.decision not in ("ask", "deny"):
        return "", 0
    verdict, reason = decision.decision, _reason(decision)
    if verdict == "ask" and not ask_supported:
        verdict, reason = "deny", reason + NEEDS_APPROVAL
    if style == "exit2":
        return reason, 2
    if style == "claude":
        return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": verdict,
                                                  "permissionDecisionReason": reason}}), 0
    if style == "copilot":
        return json.dumps({"permissionDecision": verdict, "permissionDecisionReason": reason}), 0
    if style == "gemini":
        return json.dumps({"decision": verdict, "reason": reason}), 0
    if style == "cursor":
        return json.dumps({"permission": verdict, "user_message": reason, "agent_message": reason}), 0
    if style == "devin":
        return json.dumps({"decision": "block", "reason": reason}), 0
    if style == "cline":
        return json.dumps({"cancel": True, "errorMessage": reason}), 0
    raise ValueError(f"unknown reply style {style!r}")
