"""OpenCode adapter (V1 plugin API, verified against opencode v1.19.4).

The bundled plugin (integrations/opencode/agent-ledger.js) sends one JSON envelope per event to
`agent-ledger hook --agent opencode`:

    {"agent": "opencode", "phase": "tool.before" | "tool.after" | "tool.error" | "chat.message" | "event",
     "tool": "bash", "args": {...}, "sessionID": "...", "callID": "...",
     "directory": "/repo", "worktree": "/repo",
     "output": {...},          # tool.after
     "error": "...",           # tool.error / session.error
     "prompt": "...",          # chat.message
     "event_type": "session.created" | "session.idle" | "session.deleted" | "session.error"}

`normalize` turns that into the canonical (Claude-Code-shaped) event the core understands, so
policy, redaction, storage and reports are shared. Only `render` is OpenCode-specific: the plugin
reads {"decision", "reason"} and throws to block the call.
"""

from __future__ import annotations

import json
import os
import re

from agent_ledger.adapters import claude_code as _cc
from agent_ledger.model import Decision, Event

AGENT = "opencode"

# OpenCode tool id -> (canonical tool, {opencode arg: canonical arg})
_TOOLS = {
    "bash": ("Bash", {"command": "command", "timeout": "timeout"}),
    "edit": ("Edit", {"filePath": "file_path", "oldString": "old_string", "newString": "new_string", "replaceAll": "replace_all"}),
    "write": ("Write", {"filePath": "file_path", "content": "content"}),
    "read": ("Read", {"filePath": "file_path", "offset": "offset", "limit": "limit"}),
    "glob": ("Glob", {"pattern": "pattern", "path": "path"}),
    "grep": ("Grep", {"pattern": "pattern", "path": "path", "include": "glob"}),
    "webfetch": ("WebFetch", {"url": "url", "format": "format", "timeout": "timeout"}),
    "websearch": ("WebSearch", None),
    "todowrite": ("TodoWrite", None),
    "task": ("Task", None),
    "skill": ("Skill", None),
    "question": ("AskUserQuestion", None),
}
_PHASES = {"tool.before": "PreToolUse", "tool.after": "PostToolUse", "tool.error": "PostToolUseFailure",
           "chat.message": "UserPromptSubmit"}
_EVENTS = {"session.created": "SessionStart", "session.idle": "Stop", "session.deleted": "SessionEnd",
           "session.error": "StopFailure"}
# Mirrors opencode v1 packages/opencode/src/patch/index.ts: headers match by prefix (no space
# required after the colon) and the path is trim()'d; a heredoc wrapper is stripped first.
_PATCH_HEADERS = (("*** Add File:", "write"), ("*** Update File:", "write"), ("*** Move to:", "write"),
                  ("*** Delete File:", "delete"))
_PATCH_HEREDOC = re.compile(r"^(?:cat\s+)?<<['\"]?(\w+)['\"]?\s*\n([\s\S]*?)\n\1\s*$")


def _abs(path: str, base: str | None) -> str:
    return path if os.path.isabs(path) or not base else os.path.normpath(os.path.join(base, path))


def _patch_input(args: dict, base: str | None) -> dict:
    """Every path an apply_patch touches. Scans all lines (a superset of OpenCode's Begin/End window)
    and marks the patch `unparsed` when it names no usable path, so policy can never allow it blind."""
    text = args.get("patchText") if isinstance(args.get("patchText"), str) else ""
    cleaned = text.strip()
    m = _PATCH_HEREDOC.match(cleaned)
    if m:
        cleaned = m.group(2)
    writes, deletes, unparsed = [], [], False
    for line in cleaned.split("\n"):
        for prefix, kind in _PATCH_HEADERS:
            if line.startswith(prefix):
                path = line[len(prefix):].strip()
                if not path:
                    unparsed = True
                else:
                    (deletes if kind == "delete" else writes).append(_abs(path, base))
                break
    ti = {"patch": text, "file_paths": writes, "delete_paths": deletes}
    if writes or deletes:
        ti["file_path"] = (writes or deletes)[0]
    if unparsed or (cleaned and not (writes or deletes)):
        ti["unparsed"] = True
    return ti


def normalize(env: dict) -> dict:
    """OpenCode plugin envelope -> canonical hook event dict."""
    directory = env.get("directory") or env.get("worktree")
    phase = env.get("phase")
    out = {
        "session_id": env.get("sessionID") or "unknown",
        "cwd": directory,
        "transcript_path": None,
    }
    if phase == "event":
        out["hook_event_name"] = _EVENTS.get(str(env.get("event_type")), "Notification")
        if out["hook_event_name"] == "SessionStart":
            out["source"] = "startup"
        if env.get("event_type") == "session.deleted":
            out["reason"] = "deleted"
        if env.get("error"):
            out["error"] = str(env["error"])
        return out
    out["hook_event_name"] = _PHASES.get(str(phase), "Notification")
    if phase == "chat.message":
        out["prompt"] = env.get("prompt") or ""
        return out

    tool = str(env.get("tool") or "")
    args = env.get("args") if isinstance(env.get("args"), dict) else {}
    out["tool_use_id"] = env.get("callID")
    if tool == "apply_patch":
        out["tool_name"], out["tool_input"] = "ApplyPatch", _patch_input(args, directory)
    elif tool in _TOOLS:
        name, keymap = _TOOLS[tool]
        out["tool_name"] = name
        out["tool_input"] = dict(args) if keymap is None else {keymap[k]: v for k, v in args.items() if k in keymap}
        if tool == "bash" and isinstance(args.get("workdir"), str) and args["workdir"]:
            out["cwd"] = _abs(args["workdir"], directory)
    else:
        # MCP / plugin tools: OpenCode does not mark their origin, so keep them distinct from builtins
        out["tool_name"], out["tool_input"] = f"opencode:{tool}", dict(args)
    if phase == "tool.after":
        o = env.get("output") if isinstance(env.get("output"), dict) else {}
        out["tool_response"] = {"title": o.get("title"), "output": o.get("output"), "metadata": o.get("metadata")}
    if phase == "tool.error":
        out["error"] = str(env.get("error") or "")
    return out


def to_event(data: dict, env) -> Event:
    canon = normalize(data)
    ev = _cc.to_event(canon, {})
    ev.agent = AGENT
    ev.project_dir = data.get("worktree") or data.get("directory") or canon.get("cwd")
    ev.raw = canon
    return ev


stored_payload = _cc.stored_payload
summarize = _cc.summarize
session_meta = _cc.session_meta


def render(decision: Decision | None, event_type: str, system_message: str | None = None) -> tuple[str, int]:
    """The plugin reads {"decision", "reason"} for tool.before; everything else gets no output."""
    if decision is None or event_type != "PreToolUse" or decision.decision not in ("allow", "ask", "deny"):
        return "", 0
    reason = f"agent-ledger [{decision.rule_id}]: {decision.reason or decision.rule_id}"
    return json.dumps({"decision": decision.decision, "reason": reason}), 0
