"""`agent-ledger init`: merge agent-ledger's hooks into a Claude Code settings file.

Never overwrites: other keys and other hooks are preserved, our own entries are updated
in place, the previous file is backed up to settings.json.bak, and invalid JSON aborts.
"""

from __future__ import annotations

import contextlib
import json
import os
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


def _write_new(path: Path, text: str) -> None:
    """Atomically replace `path` without ever writing through a symlink planted next to it."""
    import tempfile

    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")  # O_EXCL, random name
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)  # replaces a symlink at `path` itself; never follows it
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def write_exclusive(path: Path, text: str) -> bool:
    """Create `path` only if nothing (not even a dangling symlink) is there. Returns False if it exists."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    return True


def install_hooks(settings_path, command: str, fail_closed: bool = False) -> bool:
    """Merge hooks into `settings_path`. Returns True if the file changed."""
    path = Path(settings_path)
    if path.is_symlink():
        raise InitError(f"{path} is a symlink; refusing to modify it (it may point outside the project)")
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
        _write_new(path.with_name(path.name + ".bak"), path.read_text("utf-8"))
    _write_new(path, json.dumps(merged, indent=2) + "\n")
    return True
