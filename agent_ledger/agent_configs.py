"""`agent-ledger init --agent <name>`: write each agent's own hook configuration.

Every agent keeps hooks in its own file and layout. Each spec below says which file, how its hook
lists are laid out, the agent's event names and the shape of one entry. Contracts and versions
are listed in docs/agents.md.

- "nested": {event: [{matcher, hooks: [entry]}]} (Claude Code style; Codex, Gemini, Qwen, ...)
- "flat": {event: [entry]} (Cursor, Copilot, Crush, Windsurf)
- "kiro": a list of named hooks with a trigger
- "script": executable hook files named after the event (Cline)

Files shared with the user (settings.json and similar) are merged: other settings and hooks are
kept, and only our own entry is added or updated. Files that are agent-ledger's alone are never
overwritten unless agent-ledger wrote them. Symlinks are never followed.
"""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path

from agent_ledger.init import InitError, _write_new, write_exclusive

MARK = "agent-ledger"  # owned files carry it; merged entries are recognised by their command


class Spec:
    def __init__(self, name, path, kind, events, entry=None, wrap=("hooks",), matcher=None, owned=False, top=None,
                 scripts=None, note=None):
        self.name = name
        self.path = path            # str, or a function(project) -> relative path
        self.kind = kind
        self.events = events        # agent event name -> "pre" | "post"
        self.entry = entry or (lambda cmd, fc: {"type": "command", "command": cmd})
        self.wrap = wrap            # keys from the file's root to the event map
        self.matcher = matcher      # matcher for nested groups (None: no matcher key)
        self.owned = owned          # the file belongs to agent-ledger alone
        self.top = top or {}        # keys an owned or new file starts with
        self.scripts = scripts      # {"pre": rel path, "post": rel path}: entries run these scripts
        self.note = note

    def files(self, project) -> list[Path]:
        project = Path(project)
        if self.kind == "script":
            return [project / self.path / ev for ev in self.events]
        rel = self.path(project) if callable(self.path) else self.path
        return [project / rel]


def _crush_path(project: Path) -> str:
    for name in ("crush.json", ".crush.json"):
        if (project / name).exists() or (project / name).is_symlink():
            return name
    return ".crush.json"


_PRE_POST = {"PreToolUse": "pre", "PostToolUse": "post"}
_WINDSURF = {f"{phase}_{kind}": phase for phase in ("pre", "post")
             for kind in ("run_command", "read_code", "write_code", "mcp_tool_use")}

CONFIGS: dict[str, Spec] = {s.name: s for s in (
    Spec("codex", ".codex/hooks.json", "nested", _PRE_POST, matcher=".*",
         entry=lambda c, fc: {"type": "command", "command": c, "timeout": 10},
         note="IMPORTANT: Codex skips new hooks until you approve them. Start `codex` once in this project and "
              "approve the agent-ledger hooks in its review screen; until then Codex runs ungoverned "
              "(`codex exec` never asks)."),
    Spec("copilot", ".github/hooks/agent-ledger.json", "flat", {"preToolUse": "pre", "postToolUse": "post"}, owned=True,
         top={"version": 1}, entry=lambda c, fc: {"type": "command", "bash": c, "timeoutSec": 30}),
    Spec("cursor", ".cursor/hooks.json", "flat", {"preToolUse": "pre", "postToolUse": "post"}, top={"version": 1},
         entry=lambda c, fc: {"command": c, **({"failClosed": True} if fc else {})}),
    Spec("gemini", ".gemini/settings.json", "nested", {"BeforeTool": "pre", "AfterTool": "post"}, matcher=".*",
         note="Gemini runs project hooks only in a trusted folder."),
    Spec("antigravity", ".agents/hooks.json", "nested", _PRE_POST, wrap=("agent-ledger",), matcher=".*",
         entry=lambda c, fc: {"command": c}),
    Spec("cline", ".clinerules/hooks", "script", _PRE_POST, owned=True,
         note='The Cline CLI runs these as is. In the VS Code extension, also turn on "Enable Hooks" in Cline\'s '
              'feature settings.'),
    Spec("windsurf", ".devin/hooks.json", "flat", _WINDSURF,
         entry=lambda c, fc: {"command": c, "show_output": True}),
    Spec("goose", ".agents/plugins/agent-ledger/hooks/hooks.json", "nested", _PRE_POST, matcher=".*", owned=True,
         entry=lambda c, fc: {"type": "command", "command": c, "timeout": 30, "on_failure": "block" if fc else "allow"},
         note="Goose loads project plugins automatically, unless one is listed as disabled in "
              ".config/goose/settings.json."),
    Spec("crush", _crush_path, "flat", _PRE_POST, entry=lambda c, fc: {"command": c, "timeout": 30}),
    Spec("qwen", ".qwen/settings.json", "nested", _PRE_POST, matcher=".*"),
    Spec("continue", ".continue/settings.json", "nested", _PRE_POST, matcher="*"),
    Spec("factory", ".factory/hooks.json", "nested", _PRE_POST, wrap=(), matcher="*"),
    Spec("kiro", ".kiro/hooks/agent-ledger.json", "kiro", _PRE_POST, owned=True, top={"version": "v1"}),
    Spec("auggie", ".augment/settings.json", "nested", _PRE_POST, matcher=".*",
         entry=lambda c, fc: {"type": "command", "command": c, "timeout": 10000},
         scripts={"pre": ".augment/hooks/agent-ledger-pre.sh", "post": ".augment/hooks/agent-ledger-post.sh"}),
    Spec("devin", ".devin/hooks.v1.json", "nested", _PRE_POST, wrap=(), matcher=""),
)}


def hook_command(hook_argv: list[str], agent: str, phase: str) -> str:
    return shlex.join([*hook_argv, "--agent", agent, "--event", phase])


def _script(command: str, agent: str) -> str:
    return f"#!/bin/sh\n# {MARK} hook for {agent}: written by `agent-ledger init --agent {agent}`. Re-run init to update.\nexec {command}\n"


def _is_ours(entry, agent: str) -> bool:
    if not isinstance(entry, dict):
        return False
    cmd = entry.get("command") or entry.get("bash") or ""
    if not isinstance(cmd, str):
        return False
    cmd = cmd.replace("\\", "/")  # Windows script paths use backslashes
    return f"--agent {agent} " in cmd + " " or f"/{MARK}-pre.sh" in cmd or f"/{MARK}-post.sh" in cmd


def _load(path: Path, owned: bool) -> dict | None:
    if path.is_symlink():
        raise InitError(f"{path} is a symlink; refusing to modify it (it may point outside the project)")
    if not path.exists():
        return None
    text = path.read_text("utf-8", "replace")
    if owned and MARK not in text:
        raise InitError(f"{path} exists and was not written by agent-ledger; move it aside first")
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError as e:
        raise InitError(f"{path} is not valid JSON ({e}); fix it first, nothing was changed") from e
    if not isinstance(data, dict):
        raise InitError(f"{path} must contain a JSON object")
    return data


def _container(data: dict, wrap) -> dict:
    c = data
    for key in wrap:
        c = c.setdefault(key, {})
        if not isinstance(c, dict):
            raise InitError(f'"{key}" in the hook settings must be an object')
    return c


def _merge(spec: Spec, data: dict, commands: dict[str, str], fail_closed: bool) -> dict:
    container = _container(data, spec.wrap)
    for event, phase in spec.events.items():
        want = spec.entry(commands[phase], fail_closed)
        groups = container.setdefault(event, [])
        if not isinstance(groups, list):
            raise InitError(f'hooks for "{event}" must be a list')
        found = False
        for g in groups:
            items = g.get("hooks") if spec.kind == "nested" and isinstance(g, dict) else None
            if spec.kind == "nested":
                if not isinstance(items, list):
                    continue
                for i, h in enumerate(items):
                    if _is_ours(h, spec.name):
                        items[i] = None if found else want
                        found = True
                g["hooks"] = [h for h in items if h is not None]
        if spec.kind == "flat":
            kept = []
            for e in groups:
                if _is_ours(e, spec.name):
                    if not found:
                        kept.append(want)
                    found = True
                else:
                    kept.append(e)
            groups[:] = kept
        else:
            groups[:] = [g for g in groups if not (isinstance(g, dict) and g.get("hooks") == [])]
        if not found:
            if spec.kind == "flat":
                groups.append(want)
            else:
                groups.append({**({"matcher": spec.matcher} if spec.matcher is not None else {}), "hooks": [want]})
    return data


def _write(path: Path, text: str, executable: bool = False) -> bool:
    """Create or replace `path` (never through a symlink). Returns True if it changed."""
    if path.is_symlink():
        raise InitError(f"{path} is a symlink; refusing to modify it")
    if path.exists():
        if path.read_text("utf-8", "replace") == text:
            return False
        _write_new(path, text)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not write_exclusive(path, text):
            raise InitError(f"{path} appeared while installing; nothing more was changed")
    if executable:
        os.chmod(path, 0o755)
    return True


def install_agent(agent: str, project, hook_argv: list[str], fail_closed: bool = False) -> bool:
    """Install agent-ledger's hooks for `agent` into `project`. Returns True if anything changed.

    `hook_argv` is the agent-ledger hook command as an argv list, ending in "hook"."""
    spec = CONFIGS[agent]
    project = Path(project)
    commands = {phase: hook_command(hook_argv, agent, phase) for phase in ("pre", "post")}
    writes: list[tuple[Path, str, bool]] = []

    if spec.kind == "script":
        for path in spec.files(project):
            if path.is_symlink():
                raise InitError(f"{path} is a symlink; refusing to modify it")
            if path.exists() and MARK not in path.read_text("utf-8", "replace"):
                raise InitError(f"{path} exists and was not written by agent-ledger; move it aside first")
            writes.append((path, _script(commands[spec.events[path.name]], agent), True))
    else:
        path = spec.files(project)[0]
        if spec.scripts:  # the agent runs a script file; the script runs agent-ledger
            for phase, rel in spec.scripts.items():
                script = project / rel
                if script.is_symlink() or (script.exists() and MARK not in script.read_text("utf-8", "replace")):
                    raise InitError(f"{script} exists and was not written by agent-ledger; move it aside first")
                writes.append((script, _script(commands[phase], agent), True))
                # absolute() not resolve(): on Windows resolve() expands 8.3 short names only once the
                # file exists, which would make every re-run look like a change
                commands[phase] = str(script.absolute())
        data = _load(path, spec.owned)
        if spec.kind == "kiro":
            data = {**spec.top, "hooks": [
                {"name": f"{MARK}-{phase}", "trigger": event, "action": {"type": "command", "command": commands[phase]}}
                for event, phase in spec.events.items()]}
        else:
            data = _merge(spec, {**spec.top, **data} if data is not None else dict(spec.top), commands, fail_closed)
        if spec.owned:  # owned files always start with the marker, so a re-run produces identical text
            data = {f"_{MARK}": "written by `agent-ledger init`; re-run init to update",
                    **{k: v for k, v in data.items() if k != f"_{MARK}"}}
        writes.append((path, json.dumps(data, indent=2) + "\n", False))

    changed = False
    for path, text, executable in writes:
        changed |= _write(path, text, executable)
    return changed
