"""Profiles for agents with a command hook: `agent-ledger hook --agent <name> [--event pre|post]`.

Each profile reads one agent's hook payload (field names, tool names, argument names) into the
canonical event the core understands, and answers in that agent's reply format. Contracts were
taken from each agent's source or hook reference; docs/agents.md lists versions and sources.

`ask` is True only where the agent really shows an approval prompt for a hook's "ask". Elsewhere
"ask" is answered as a block that says the call needs human approval (generic.render_decision).
"""

from __future__ import annotations

import json
import os
import re
import shlex

from agent_ledger.adapters import claude_code as _cc
from agent_ledger.adapters.generic import infer_action, render_decision
from agent_ledger.model import Decision, Event

# agent event names -> canonical (Claude Code) event names
_EVENTS = {
    "pretooluse": "PreToolUse", "beforetool": "PreToolUse", "toolcall": "PreToolUse", "pre": "PreToolUse",
    "posttooluse": "PostToolUse", "aftertool": "PostToolUse", "toolresult": "PostToolUse", "post": "PostToolUse",
    "posttoolusefailure": "PostToolUseFailure", "sessionstart": "SessionStart", "sessionend": "SessionEnd",
    "userpromptsubmit": "UserPromptSubmit", "userpromptsubmitted": "UserPromptSubmit", "beforeagent": "UserPromptSubmit",
    "stop": "Stop", "notification": "Notification",
}
_URL = re.compile(r"https?://[^\s'\"<>`)\]]+", re.I)


class Profile:
    def __init__(self, name, style, ask, names=None, rename=None, mcp_prefix=None, event_key=None, bridge=None):
        self.name = name
        self.style = style          # reply style, see generic.render_decision
        self.ask = ask              # does the agent show an approval prompt for "ask"?
        self.names = names or {}    # exact tool name -> canonical tool (checked before the shared table)
        self.rename = rename or {}  # argument name -> canonical argument name
        self.mcp_prefix = mcp_prefix  # how the agent prefixes MCP tool names, e.g. "mcp_"
        self.event_key = event_key
        self.bridge = bridge        # a wrapper tool that calls another tool by name ({name, args})

    # ------------------------------------------------------------ payload -> canonical

    def fields(self, data: dict) -> dict:
        """event, tool, args, session, cwd, response from the agent's payload (overridden per agent)."""
        roots = data.get("workspace_roots") or data.get("workspaceRoots") or data.get("workspacePaths")
        root = roots[0] if isinstance(roots, list) and roots and isinstance(roots[0], str) else None
        return {
            "event": data.get("hook_event_name") or data.get("hookEventName") or data.get("event"),
            "tool": data.get("tool_name") or data.get("toolName"),
            "args": data.get("tool_input") if "tool_input" in data else data.get("toolArgs"),
            "session": data.get("session_id") or data.get("sessionId") or data.get("conversation_id"),
            "cwd": data.get("cwd") or data.get("working_dir") or root,
            "response": data.get("tool_response", data.get("tool_output", data.get("toolResult"))),
            "prompt": data.get("prompt"),
        }

    def tool(self, name: str, args, cwd: str | None) -> tuple[str, dict, str | None]:
        """(canonical tool, tool_input, shell cwd override)."""
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except ValueError:
                args = {"input": args}
        args = args if isinstance(args, dict) else {"input": args}
        if self.bridge and name == self.bridge and isinstance(args.get("name"), str):
            inner = args.get("args", args.get("arguments"))
            return self.tool(args["name"], inner if isinstance(inner, (dict, str)) else {}, cwd)
        args = {self.rename.get(k, k): v for k, v in args.items()}
        name = str(name or "")
        if self.mcp_prefix and name.startswith(self.mcp_prefix) and not name.startswith("mcp__"):
            name = "mcp__" + name[len(self.mcp_prefix):]
        canon = self.names.get(name)
        special = _SPECIAL.get(canon)
        if special:
            return special(args, cwd) + (None,)
        tool, ti = infer_action(name, args, cwd=cwd, agent=self.name, names={name: canon} if canon else None)
        shell_cwd = None
        if tool == "Bash":
            d = next((args[k] for k in ("cwd", "workdir", "working_dir", "working_directory", "dir_path", "directory")
                      if isinstance(args.get(k), str) and args[k]), None)
            if d:
                shell_cwd = d if os.path.isabs(d) or not cwd else os.path.normpath(os.path.join(cwd, d))
        return tool, ti, shell_cwd

    def normalize(self, data: dict, event: str | None = None) -> dict:
        f = self.fields(data)
        ev_name = event or f["event"] or ("PreToolUse" if f["tool"] else None)
        canon = _EVENTS.get(str(ev_name or "").replace("_", "").lower(), str(ev_name or "Notification"))
        cwd = f["cwd"] if isinstance(f["cwd"], str) and f["cwd"] else os.getcwd()
        out = {"session_id": str(f["session"] or "unknown"), "cwd": cwd, "hook_event_name": canon, "_project": cwd,
               "transcript_path": data.get("transcript_path") if isinstance(data.get("transcript_path"), str) else None}
        if canon == "UserPromptSubmit":
            out["prompt"] = str(f["prompt"] or "")
        if canon in _cc.TOOL_EVENTS and f["tool"]:
            tool, ti, shell_cwd = self.tool(f["tool"], f["args"], cwd)
            out["tool_name"], out["tool_input"] = tool, ti
            out["tool_use_id"] = data.get("tool_use_id") or data.get("tool_call_id") or data.get("toolUseId")
            if shell_cwd:
                out["cwd"] = shell_cwd
            if canon != "PreToolUse" and f["response"] is not None:
                out["tool_response"] = f["response"]
        return out

    # ------------------------------------------------------------ adapter interface used by hook.py

    def to_event(self, data: dict, env, event: str | None = None) -> Event:
        canon = self.normalize(data, event)
        project = canon.pop("_project")
        ev = _cc.to_event(canon, {})
        ev.agent = self.name
        ev.project_dir = project
        ev.raw = canon
        return ev

    stored_payload = staticmethod(_cc.stored_payload)
    summarize = staticmethod(_cc.summarize)
    session_meta = staticmethod(_cc.session_meta)

    def render(self, decision: Decision | None, event_type: str, system_message: str | None = None) -> tuple[str, int]:
        if event_type != "PreToolUse":
            return "", 0
        return render_decision(decision, self.style, self.ask)


# ---------------------------------------------------------------- canonical pseudo-tools

def _paths(args: dict, cwd) -> list[str]:
    raw = []
    for k in ("file_path", "path", "paths", "file_paths", "files", "include", "operations"):
        v = args.get(k)
        for item in (v if isinstance(v, list) else [v]):
            p = item.get("path") if isinstance(item, dict) else item
            if isinstance(p, str) and p:
                raw.append(p)
    return [p if os.path.isabs(p) or not cwd else os.path.normpath(os.path.join(cwd, p)) for p in raw]


def _delete(args, cwd):
    """A delete tool is checked as the equivalent `rm`, so every delete rule applies."""
    paths = _paths(args, cwd)
    return "Bash", {"command": shlex.join(["rm", "-rf", "--", *paths]) if paths else "rm"}


def _download(args, cwd):
    """Download to a file = fetch (host checked) + write (target checked)."""
    target = _paths({"file_path": args.get("file_path") or args.get("path")}, cwd)
    return "Bash", {"command": shlex.join(["curl", "-o", target[0] if target else "", str(args.get("url") or "")])}


def _read_many(args, cwd):
    paths = _paths(args, cwd)
    return "Read", {"file_paths": paths, **({"file_path": paths[0]} if paths else {})}


def _fetch_urls(args, cwd):
    urls = []
    for k in ("url", "urls", "requests", "prompt"):
        v = args.get(k)
        for item in (v if isinstance(v, list) else [v]):
            u = item.get("url") if isinstance(item, dict) else item
            if isinstance(u, str):
                urls += _URL.findall(u) if k == "prompt" else [u]
    return "WebFetch", {"url": urls[0] if urls else "", "urls": urls}


def _editor(args, cwd):
    """Cline's editor: no old_text means it creates (or overwrites) the file."""
    path = _paths({"path": args.get("path")}, cwd)
    ti = {"file_path": path[0] if path else "", "content": args.get("new_text")}
    if args.get("old_text") is not None:
        return "Edit", {"file_path": ti["file_path"], "old_string": args.get("old_text"), "new_string": args.get("new_text")}
    return "Write", ti


_SPECIAL = {"Delete": _delete, "Download": _download, "ReadMany": _read_many, "FetchUrls": _fetch_urls,
            "ClineEditor": _editor}


# ---------------------------------------------------------------- agents with their own payload shapes

class _Copilot(Profile):
    def fields(self, data):
        f = super().fields(data)
        f["event"] = f["event"] or data.get("hookEventName")
        return f


class _Cursor(Profile):
    def fields(self, data):
        f = super().fields(data)
        ev = str(f["event"] or "")
        if ev == "beforeShellExecution":
            f.update(event="PreToolUse", tool="Shell", args={"command": data.get("command")})
        elif ev == "beforeReadFile":
            f.update(event="PreToolUse", tool="Read", args={"file_path": data.get("file_path")})
        elif ev == "beforeMCPExecution":
            f.update(event="PreToolUse", tool="MCP:" + str(data.get("tool_name")), args=data.get("tool_input"))
        if isinstance(f["tool"], str) and f["tool"].startswith("MCP:"):
            f["tool"] = "mcp__" + f["tool"][4:]
        if isinstance(f["args"], dict) and isinstance(f["args"].get("working_directory"), str):
            f["cwd"] = f["cwd"] or f["args"]["working_directory"]
        return f


class _Antigravity(Profile):
    def fields(self, data):
        f = super().fields(data)
        call = data.get("toolCall") if isinstance(data.get("toolCall"), dict) else {}
        f.update(tool=call.get("name"), args=call.get("args"), session=data.get("conversationId"),
                 event=f["event"] or ("PostToolUse" if "error" in data or "result" in data else "PreToolUse"))
        return f


class _Cline(Profile):
    def fields(self, data):
        f = super().fields(data)
        f["session"] = data.get("taskId") or f["session"]
        f["event"] = data.get("hookName") or f["event"]
        call = data.get("tool_call") if isinstance(data.get("tool_call"), dict) else None
        vs = data.get("preToolUse") or data.get("postToolUse")
        if call:
            f.update(tool=call.get("name"), args=call.get("input"))
            f["response"] = data.get("tool_result")
        elif isinstance(vs, dict):  # VS Code extension: every parameter value is a string
            params = vs.get("parameters") if isinstance(vs.get("parameters"), dict) else {}
            args = {}
            for k, v in params.items():
                if isinstance(v, str) and v[:1] in "[{":
                    try:
                        v = json.loads(v)
                    except ValueError:
                        pass
                args[k] = v
            f.update(tool=vs.get("toolName"), args=args,
                     event="PostToolUse" if "postToolUse" in data else "PreToolUse")
            f["response"] = vs.get("result")
        return f


class _Windsurf(Profile):
    _ACTIONS = {"run_command": "Shell", "read_code": "Read", "write_code": "Write", "mcp_tool_use": None}

    def fields(self, data):
        info = data.get("tool_info") if isinstance(data.get("tool_info"), dict) else {}
        action = str(data.get("agent_action_name") or "")
        phase, _, kind = action.partition("_")
        f = {"event": {"pre": "PreToolUse", "post": "PostToolUse"}.get(phase, action), "session": data.get("trajectory_id"),
             "cwd": info.get("cwd"), "response": None, "prompt": data.get("user_prompt"), "tool": None, "args": None}
        if kind == "run_command":
            f.update(tool="Shell", args={"command": info.get("command_line")})
        elif kind in ("read_code", "write_code"):
            f.update(tool=self._ACTIONS[kind], args={"file_path": info.get("file_path"), "edits": info.get("edits")})
        elif kind == "mcp_tool_use":
            f.update(tool=f"mcp__{info.get('mcp_server_name')}__{info.get('mcp_tool_name')}",
                     args=info.get("mcp_tool_arguments"))
        elif kind == "user_prompt":
            f["event"] = "UserPromptSubmit"
        return f


class _Auggie(Profile):
    def fields(self, data):
        f = super().fields(data)
        if data.get("is_mcp_tool") and isinstance(f["tool"], str) and not f["tool"].startswith("mcp__"):
            f["tool"] = "mcp__" + f["tool"]
        f["response"] = data.get("tool_output") if data.get("tool_error") is None else data.get("tool_error")
        return f


_CLAUDE_LIKE = {"Bash": "Bash", "Read": "Read", "Write": "Write", "Edit": "Edit", "MultiEdit": "MultiEdit",
                "Glob": "Glob", "Grep": "Grep", "LS": "LS", "WebFetch": "WebFetch", "WebSearch": "WebSearch",
                "Task": "Task", "TodoWrite": "TodoWrite"}

PROFILES: dict[str, Profile] = {p.name: p for p in (
    # Claude-shaped payloads; "ask" is rejected by Codex, and a bare "allow" needs updatedInput
    Profile("codex", "claude", ask=False, names={"apply_patch": "ApplyPatch", "spawn_agent": "Task",
                                                 "update_plan": "TodoWrite", "request_user_input": "AskUserQuestion",
                                                 "view_image": "Read"}),
    _Copilot("copilot", "copilot", ask=True, names={**_CLAUDE_LIKE, "bash": "Bash", "powershell": "Bash", "view": "Read",
                                                    "create": "Write", "edit": "Edit", "glob": "Glob", "grep": "Grep",
                                                    "web_fetch": "WebFetch", "task": "Task", "ask_user": "AskUserQuestion"}),
    # Cursor's schema has "ask" but does not enforce it yet
    _Cursor("cursor", "cursor", ask=False, names={"Shell": "Bash", "Read": "Read", "Write": "Write", "Grep": "Grep",
                                                  "Delete": "Delete", "Task": "Task"}),
    Profile("gemini", "gemini", ask=True, mcp_prefix="mcp_",
            names={"read_many_files": "ReadMany", "web_fetch": "FetchUrls", "list_directory": "LS",
                   "write_todos": "TodoWrite", "ask_user": "AskUserQuestion", "enter_plan_mode": "EnterPlanMode",
                   "exit_plan_mode": "ExitPlanMode", "activate_skill": "Skill", "invoke_agent": "Task"},
            rename={"dir_path": "path", "include_pattern": "glob", "start_line": "offset"}),
    _Antigravity("antigravity", "gemini", ask=True,
                 names={"run_command": "Bash", "view_file": "Read", "write_to_file": "Write",
                        "replace_file_content": "Edit", "multi_replace_file_content": "Edit", "find_by_name": "Glob",
                        "grep_search": "Grep", "list_dir": "LS", "read_url_content": "WebFetch", "search_web": "WebSearch",
                        "manage_task": "TodoWrite", "ask_question": "AskUserQuestion", "invoke_subagent": "Task"},
                 rename={"CommandLine": "command", "Cwd": "cwd", "AbsolutePath": "file_path", "TargetFile": "file_path",
                         "CodeContent": "content", "TargetContent": "old_string", "ReplacementContent": "new_string",
                         "SearchDirectory": "path", "SearchPath": "path", "DirectoryPath": "path", "Pattern": "pattern",
                         "Query": "pattern", "Includes": "glob", "Url": "url"}),
    _Cline("cline", "cline", ask=False,
           names={"run_commands": "Bash", "read_files": "ReadMany", "editor": "ClineEditor", "apply_patch": "ApplyPatch",
                  "search_codebase": "Grep", "fetch_web_content": "FetchUrls", "skills": "Skill",
                  "ask_question": "AskUserQuestion"},
           rename={"queries": "pattern"}),
    _Windsurf("windsurf", "exit2", ask=False, names={"Shell": "Bash", "Read": "Read", "Write": "Write"}),
    # extensionmanager__* are Goose's own platform tools; manage_extensions (turns tools on) is left unknown
    Profile("goose", "exit2", ask=False, names={"shell": "Bash", "write": "Write", "edit": "Edit", "tree": "LS",
                                                "read_image": "Read", "load_skill": "Skill",
                                                "extensionmanager__list_resources": "ListMcpResourcesTool",
                                                "extensionmanager__read_resource": "ReadMcpResourceTool",
                                                "extensionmanager__search_available_extensions": "ToolSearch"},
            rename={"before": "old_string", "after": "new_string"}),
    Profile("crush", "claude", ask=False, mcp_prefix="mcp_",
            names={"bash": "Bash", "view": "Read", "write": "Write", "edit": "Edit", "multiedit": "MultiEdit",
                   "glob": "Glob", "grep": "Grep", "ls": "LS", "fetch": "WebFetch", "web_fetch": "WebFetch",
                   "agentic_fetch": "FetchUrls", "download": "Download", "web_search": "WebSearch",
                   "sourcegraph": "WebSearch", "todos": "TodoWrite", "question": "AskUserQuestion", "agent": "Task"},
            rename={"include": "glob"}),
    Profile("qwen", "claude", ask=True, bridge="tool_call", names={"edit": "Edit", "list_directory": "LS", "todo_write": "TodoWrite",
                                               "agent": "Task", "skill": "Skill", "ask_user_question": "AskUserQuestion"}),
    Profile("continue", "claude", ask=True,
            names={**_CLAUDE_LIKE, "Search": "Grep", "List": "LS", "Fetch": "WebFetch", "Subagent": "Task",
                   "Checklist": "TodoWrite", "AskQuestion": "AskUserQuestion", "Skills": "Skill"},
            rename={"filepath": "file_path", "dirpath": "path", "file_pattern": "glob"}),
    Profile("factory", "claude", ask=True,
            names={**_CLAUDE_LIKE, "Execute": "Bash", "Create": "Write", "ApplyPatch": "ApplyPatch", "FetchUrl": "WebFetch"}),
    Profile("kiro", "exit2", ask=False, mcp_prefix="mcp_",
            names={"execute_bash": "Bash", "execute_pwsh": "Bash", "read_file": "Read", "fs_read": "ReadMany",
                   "fs_write": "Write", "fs_append": "Write", "str_replace": "Edit", "delete_file": "Delete",
                   "file_search": "Glob", "grep_search": "Grep", "list_directory": "LS", "web_fetch": "WebFetch",
                   "remote_web_search": "WebSearch", "invoke_sub_agent": "Task"}),
    # Auggie supports only "deny" from a hook
    _Auggie("auggie", "claude", ask=False,
            names={"launch-process": "Bash", "view": "Read", "save-file": "Write", "str-replace-editor": "Edit",
                   "remove-files": "Delete", "web-fetch": "WebFetch", "web-search": "WebSearch",
                   "codebase-retrieval": "Grep"}),
    Profile("devin", "devin", ask=False,
            names={"exec": "Bash", "read": "Read", "write": "Write", "edit": "Edit", "apply_patch": "ApplyPatch",
                   "grep": "Grep", "glob": "Glob", "webfetch": "WebFetch", "todo_write": "TodoWrite",
                   "exit_plan_mode": "ExitPlanMode", "skill": "Skill", "run_subagent": "Task"}),
)}


# ---------------------------------------------------------------- agents governed through a plugin

class _Amp(Profile):
    """Envelopes from integrations/amp/agent-ledger.ts. The plugin passes the shell command Amp's own
    helper extracted (amp.helpers.shellCommandFromToolCall) when there is one."""

    def fields(self, data):
        phase = data.get("phase")
        f = {"event": {"tool.before": "PreToolUse", "tool.after": "PostToolUse", "tool.error": "PostToolUseFailure"}.get(phase),
             "tool": data.get("tool"), "args": data.get("args"), "session": data.get("sessionID"),
             "cwd": data.get("directory"), "response": data.get("output") if phase == "tool.after" else data.get("error"),
             "prompt": None}
        shell = data.get("shell")
        if isinstance(shell, dict) and isinstance(shell.get("command"), str):
            f.update(tool="Bash", args={"command": shell["command"], **({"cwd": shell["dir"]} if shell.get("dir") else {})})
        return f


PLUGIN_PROFILES: dict[str, Profile] = {p.name: p for p in (
    # the plugin asks through Amp's own ctx.ui.confirm, and rejects when it cannot
    _Amp("amp", "plugin", ask=True,
         names={"Bash": "Bash", "shell_command": "Bash", "Read": "Read", "edit_file": "Edit", "create_file": "Write",
                "read_web_page": "WebFetch", "web_search": "WebSearch", "Grep": "Grep", "glob": "Glob", "Task": "Task",
                "todo_write": "TodoWrite"}),
)}
