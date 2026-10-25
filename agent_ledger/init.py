"""`agent-ledger init`: merge agent-ledger's hooks into a Claude Code settings file.

Never overwrites: other keys and other hooks are preserved, our own entries are updated
in place, the previous file is backed up to settings.json.bak, and invalid JSON aborts.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

HOOK_EVENTS = (
    "SessionStart", "UserPromptSubmit", "PreToolUse", "PermissionRequest", "PermissionDenied",
    "PostToolUse", "PostToolUseFailure", "Stop", "SubagentStart", "SubagentStop", "SessionEnd",
    "ConfigChange",
)
TOOL_EVENTS = {"PreToolUse", "PermissionRequest", "PermissionDenied", "PostToolUse", "PostToolUseFailure"}
TIMEOUT = 10
MARKERS = ("agent-ledger", "agent_ledger")


class InitError(Exception):
    pass


def _is_ours(handler: dict) -> bool:
    cmd = handler.get("command", "")
    return isinstance(cmd, str) and any(m in cmd for m in MARKERS) and cmd.rstrip().endswith(" hook")


def _handler(command: str, event: str, fail_closed: bool) -> dict:
    h = {"type": "command", "command": command, "timeout": TIMEOUT}
    if fail_closed and event == "PreToolUse":
        h["onFailure"] = "block"  # Claude Code >= 2.1.295: also block when the hook cannot start
    return h


def merge_hooks(settings: dict, command: str, fail_closed: bool = False, events=HOOK_EVENTS):
    if not isinstance(settings, dict):
        raise InitError("settings file must contain a JSON object")
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise InitError('"hooks" in settings must be an object')
    before = json.dumps(settings, sort_keys=True)
    for event in events:
        groups = hooks.setdefault(event, [])
        if not isinstance(groups, list):
            raise InitError(f'"hooks.{event}" must be a list')
        want = _handler(command, event, fail_closed)
        found = False
        for g in groups:
            hs = g.get("hooks", []) if isinstance(g, dict) else []
            for i, h in enumerate(hs):
                if isinstance(h, dict) and _is_ours(h):
                    if found:
                        hs[i] = None  # drop duplicates of our own handler
                    else:
                        hs[i] = want
                        found = True
            if isinstance(g, dict) and isinstance(g.get("hooks"), list):
                g["hooks"] = [h for h in g["hooks"] if h is not None]
        groups[:] = [g for g in groups if not (isinstance(g, dict) and g.get("hooks") == [])]
        if not found:
            group = {"hooks": [want]}
            if event in TOOL_EVENTS:
                group = {"matcher": "*", **group}
            groups.append(group)
    return settings, json.dumps(settings, sort_keys=True) != before


def install_hooks(settings_path, command: str, fail_closed: bool = False) -> bool:
    """Merge hooks into `settings_path`. Returns True if the file changed."""
    path = Path(settings_path)
    settings: dict = {}
    if path.exists():
        try:
            settings = json.loads(path.read_text("utf-8") or "{}")
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise InitError(f"{path} is not valid JSON ({e}); fix it first, nothing was changed") from e
    merged, changed = merge_hooks(settings, command, fail_closed)
    if not changed:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, path.with_name(path.name + ".bak"))
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(merged, indent=2) + "\n", "utf-8")
    os.replace(tmp, path)
    return True
