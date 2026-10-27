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
    if os.path.lexists(path):  # Windows has no O_NOFOLLOW, and its O_EXCL follows a dangling symlink
        return False
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


# ---------------------------------------------------------------- OpenCode

OPENCODE_TEMPLATE = Path(__file__).with_name("integrations") / "opencode" / "agent-ledger.js"
OPENCODE_MARKER = "agent-ledger-plugin:"  # any version of our own plugin (v1, v2, ...) may be upgraded


def render_opencode_plugin(hook_argv: list[str], fail_closed: bool = False) -> str:
    """The plugin source with the hook command baked in as an argv array (no shell, no PATH lookup)."""
    src = OPENCODE_TEMPLATE.read_text("utf-8")
    return src.replace("__HOOK_ARGV__", json.dumps(list(hook_argv))).replace(
        "__FAIL_CLOSED__", "true" if fail_closed else "false"
    )


def install_opencode_plugin(project: Path, hook_argv: list[str], fail_closed: bool = False,
                            dest: str = ".opencode/plugins") -> bool:
    """Install the plugin as <project>/<dest>/agent-ledger.js. Returns True if it changed.

    `dest` is ".kilo/plugins" for Kilo Code, which runs OpenCode's V1 plugin API.
    Never follows a symlink there and never overwrites a file that agent-ledger did not write.
    """
    return _install_plugin_file(Path(project) / dest / "agent-ledger.js", render_opencode_plugin(hook_argv, fail_closed),
                                OPENCODE_MARKER)


def _install_plugin_file(path: Path, text: str, marker: str) -> bool:
    if path.is_symlink():
        raise InitError(f"{path} is a symlink; refusing to modify it")
    if path.exists():
        current = path.read_text("utf-8", "replace")
        if marker not in current:
            raise InitError(f"{path} exists and was not written by agent-ledger; move it aside first")
        if current == text:
            return False
        _write_new(path, text)
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    if not write_exclusive(path, text):
        raise InitError(f"{path} appeared while installing; nothing was changed")
    return True


GIT_HOOK_MARKER = "agent-ledger-git-hook"
GIT_HOOKS = ("pre-commit", "pre-push")


def _git_hooks_dir(repo: Path) -> Path:
    import subprocess

    try:
        out = subprocess.run(["git", "-c", "core.fsmonitor=false", "rev-parse", "--git-path", "hooks"], cwd=repo,
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as e:
        raise InitError(f"cannot run git: {e}") from e
    if out.returncode != 0 or not out.stdout.strip():
        raise InitError(f"{repo} is not a git repository")
    return (Path(repo) / out.stdout.strip()).resolve()


def render_git_hook(kind: str, cli_argv: list[str]) -> str:
    import shlex

    cmd = " ".join(shlex.quote(a) for a in [*cli_argv, "git-hook", kind])
    return (f"#!/bin/sh\n# {GIT_HOOK_MARKER}: installed by `agent-ledger init --agent git`. "
            f"Re-run init to update it.\nexec {cmd} \"$@\"\n")


def install_git_hooks(repo: Path, cli_argv: list[str]) -> bool:
    """Install pre-commit and pre-push hooks (honouring core.hooksPath). Returns True if any changed.

    Never follows a symlink and never overwrites a hook that agent-ledger did not write: a
    project's own hooks are left alone, and the error says how to chain them."""
    hooks = _git_hooks_dir(repo)
    planned = []
    for kind in GIT_HOOKS:
        path = hooks / kind
        text = render_git_hook(kind, cli_argv)
        if path.is_symlink():
            raise InitError(f"{path} is a symlink; refusing to modify it")
        if path.exists():
            current = path.read_text("utf-8", "replace")
            if GIT_HOOK_MARKER not in current:
                raise InitError(f"{path} already exists and was not written by agent-ledger. Add this line to it "
                                f"instead: {' '.join([*cli_argv, 'git-hook', kind])} \"$@\" || exit 1")
            if current == text:
                continue
        planned.append((path, text))
    for path, text in planned:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            _write_new(path, text)
        elif not write_exclusive(path, text):
            raise InitError(f"{path} appeared while installing; nothing more was changed")
        os.chmod(path, 0o755)
    return bool(planned)


# ---------------------------------------------------------------- Amp

AMP_TEMPLATE = Path(__file__).with_name("integrations") / "amp" / "agent-ledger.ts"
AMP_MARKER = "agent-ledger-plugin:amp"


def render_amp_plugin(hook_argv: list[str], fail_closed: bool = False) -> str:
    src = AMP_TEMPLATE.read_text("utf-8")
    return src.replace("__HOOK_ARGV__", json.dumps(list(hook_argv))).replace(
        "__FAIL_CLOSED__", "true" if fail_closed else "false")


def install_amp_plugin(project: Path, hook_argv: list[str], fail_closed: bool = False) -> bool:
    """Install the plugin as <project>/.amp/plugins/agent-ledger.ts. Returns True if it changed."""
    return _install_plugin_file(Path(project) / ".amp" / "plugins" / "agent-ledger.ts",
                                render_amp_plugin(hook_argv, fail_closed), AMP_MARKER)
