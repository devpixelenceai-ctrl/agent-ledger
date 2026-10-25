"""Claude Code hook adapter: hook JSON <-> agent-ledger Event / Decision. See docs/hook-contract.md."""

from __future__ import annotations

import json
import re

from agent_ledger.gitinfo import git_info
from agent_ledger.model import Decision, Event
from agent_ledger.redact import redact_event_payload, redact_str

AGENT = "claude-code"
TOOL_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionRequest", "PermissionDenied")
_DROP = ("session_id", "transcript_path", "hook_event_name", "tool_name", "tool_use_id")
_TRAILING_TOKEN = re.compile(r"[A-Za-z0-9_\-+/=.:]+$")
SUMMARY_MAX = 200


def to_event(data: dict, env) -> Event:
    cwd = data.get("cwd")
    return Event(
        agent=AGENT,
        session_id=str(data.get("session_id") or "unknown"),
        event_type=str(data.get("hook_event_name") or "Unknown"),
        tool_name=data.get("tool_name"),
        tool_use_id=data.get("tool_use_id"),
        cwd=cwd,
        project_dir=env.get("CLAUDE_PROJECT_DIR") or cwd,
        raw=data,
    )


def _one_line(s: str) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= SUMMARY_MAX else s[: SUMMARY_MAX - 1] + "…"


def _tool_detail(tool: str, ti: dict) -> str | None:
    if tool.startswith("mcp__"):
        return None
    for k in ("command", "file_path", "notebook_path", "url", "pattern", "query", "description"):
        v = ti.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def summarize(data: dict) -> str:
    et = data.get("hook_event_name")
    if et in TOOL_EVENTS:
        tool = str(data.get("tool_name") or "?")
        ti = data.get("tool_input") if isinstance(data.get("tool_input"), dict) else {}
        detail = _tool_detail(tool, ti)
        s = f"{tool}: {detail}" if detail else tool
    elif et == "UserPromptSubmit":
        s = f"Prompt: {data.get('prompt', '')}"
    elif et == "SessionStart":
        s = f"Session start ({data.get('source', '?')})"
    elif et == "SessionEnd":
        s = f"Session end ({data.get('reason', '?')})"
    elif et in ("SubagentStart", "SubagentStop"):
        s = f"{et} ({data.get('agent_type', '?')})"
    elif et == "Notification":
        s = f"Notification: {data.get('message', '')}"
    else:
        s = str(et or "Unknown event")
    return _one_line(redact_str(s))


def _cap(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    cut = _TRAILING_TOKEN.sub("", s[:n])  # never keep a half token: it could be a secret prefix
    return f"{cut}…[truncated {len(s) - len(cut)} chars]"


def _map_strings(obj, fn):
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, dict):
        return {k: _map_strings(v, fn) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_map_strings(v, fn) for v in obj]
    return obj


def _omit_content(obj):
    if isinstance(obj, dict):
        return {
            k: (f"[omitted: {len(v)} chars]" if k == "content" and isinstance(v, str) else _omit_content(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_omit_content(v) for v in obj]
    return obj


def stored_payload(data: dict, max_chars: int) -> dict:
    """What we persist: redacted, size-capped, without fields already stored as columns."""
    p = {k: v for k, v in data.items() if k not in _DROP}
    if data.get("tool_name") == "Read" and "tool_response" in p:
        p["tool_response"] = _omit_content(p["tool_response"])  # file bodies add risk, not audit value
    p = _map_strings(p, lambda s: _cap(s, max_chars * 2))  # bound redaction cost on huge inputs
    p = redact_event_payload(p)
    return _map_strings(p, lambda s: _cap(s, max_chars))


def session_meta(data: dict) -> dict:
    et = data.get("hook_event_name")
    meta = {"cwd": data.get("cwd")}
    if et == "SessionStart":
        branch, commit = git_info(data.get("cwd"))
        meta.update(git_branch=branch, git_commit=commit, model=data.get("model"),
                    transcript_path=data.get("transcript_path"))
    elif et == "SessionEnd":
        meta["end_reason"] = data.get("reason")
    return meta


def render(decision: Decision | None, event_type: str, system_message: str | None = None) -> tuple[str, int]:
    """Turn a decision into (stdout, exit_code). Only PreToolUse carries a decision."""
    if decision is None or event_type != "PreToolUse" or decision.decision not in ("allow", "ask", "deny"):
        if system_message:
            return json.dumps({"systemMessage": system_message[:2000]}), 0
        return "", 0
    reason = f"agent-ledger [{decision.rule_id}]: {decision.reason or decision.rule_id}"
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision.decision,
            "permissionDecisionReason": reason,
        }
    }
    return json.dumps(out), 0
