"""`agent-ledger doctor`: is every agent set up in this project really governed?

An agent can have agent-ledger's hooks installed and still run ungoverned: Codex skips hooks you
haven't approved, Gemini ignores project hooks outside trusted folders, Cline's VS Code extension needs
"Enable Hooks", and Goose skips plugins listed as disabled. A hook that can't start fails open, silently. doctor checks, for
every agent set up in the project:

- the hook entry is there, and the command it runs exists;
- the ledger has recorded at least one event from that agent in this project;

plus the project policy (present and trusted) and recent hook errors. Exit code 0 means all good.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import time
from pathlib import Path

from agent_ledger.agent_configs import CONFIGS, _is_ours
from agent_ledger.config import ledger_home, load_config

# What to do when an agent's hooks are installed but have never fired
HINTS = {
    "codex": "Codex skips hooks you haven't approved, and `codex exec` never asks: start `codex` in this project "
             "once and approve the agent-ledger hooks.",
    "gemini": "Gemini only runs project hooks in trusted folders: trust this folder when Gemini asks.",
    "qwen": "If Qwen's folder trust is on, trust this folder.",
    "cline": 'In the VS Code extension, turn on "Enable Hooks" in Cline\'s feature settings (the CLI needs nothing).',
    "goose": "Goose skips plugins listed as disabled: check that agent-ledger isn't under \"disabled\" in "
             ".config/goose/settings.json or settings.local.json.",
    "continue": "Your Continue version may not fire pre-tool hooks yet (see docs/agents.md).",
    "cursor": "Restart Cursor so it reloads .cursor/hooks.json.",
    "windsurf": "Restart Windsurf so it reloads .devin/hooks.json.",
    "copilot": "Restart Copilot CLI so it reloads .github/hooks.",
    "kilo": "Restart Kilo Code so it loads .kilo/plugins.",
    "amp": "Plugins run in the Amp CLI only: restart it in this project.",
    "opencode": "Restart OpenCode in this project so it loads .opencode/plugins.",
    "git": "Git hooks fire on commit and push. Aider skips them unless run with --git-commit-verify.",
}
ERRORS_RECENT_S = 24 * 3600


def _commands_in_json(obj, agent: str) -> list[str]:
    out = []
    if isinstance(obj, dict):
        if _is_ours(obj, agent):
            out.append(obj.get("command") or obj.get("bash"))
        for v in obj.values():
            out += _commands_in_json(v, agent)
    elif isinstance(obj, list):
        for v in obj:
            out += _commands_in_json(v, agent)
    return out


def _exec_line(text: str) -> str | None:
    m = re.search(r"^exec (.+?)(?: \"\$@\")?$", text, re.M)
    return m.group(1) if m else None


def _read(path: Path) -> str | None:
    try:
        return path.read_text("utf-8", "replace") if path.is_file() else None
    except OSError:
        return None


def detect(project: Path) -> dict[str, list[str]]:
    """Agents set up in `project` -> the hook commands they run (empty list: set up, command unreadable)."""
    found: dict[str, list[str]] = {}
    for name in ("settings.json", "settings.local.json"):
        text = _read(project / ".claude" / name)
        if text:
            try:
                hooks = json.loads(text).get("hooks", {})
            except (ValueError, AttributeError):
                continue
            cmds = [h.get("command") for groups in hooks.values() if isinstance(groups, list) for g in groups
                    if isinstance(g, dict) for h in g.get("hooks", []) if isinstance(h, dict)
                    and isinstance(h.get("command"), str) and re.search(r"agent[-_]ledger", h["command"])
                    and h["command"].rstrip().endswith(" hook")]
            if cmds:
                found.setdefault("claude-code", []).extend(cmds)
    for agent, spec in CONFIGS.items():
        cmds = []
        for path in spec.files(project):
            text = _read(path)
            if not text or "agent" not in text:
                continue
            if spec.kind == "script":
                line = _exec_line(text)
                cmds += [line] if line and "agent-ledger" in text else []
                continue
            try:
                cmds += _commands_in_json(json.loads(text), agent)
            except ValueError:
                continue
        # Auggie's settings run wrapper scripts; the script holds the real command
        cmds = [(_exec_line(_read(Path(c)) or "") or c) if c.endswith(".sh") else c for c in cmds]
        if cmds:
            found[agent] = cmds
    for agent, rel in (("opencode", ".opencode/plugins/agent-ledger.js"), ("kilo", ".kilo/plugins/agent-ledger.js"),
                       ("amp", ".amp/plugins/agent-ledger.ts")):
        text = _read(project / rel)
        if text and "agent-ledger-plugin:" in text:
            m = re.search(r"^const HOOK = (\[.*\])$", text, re.M)
            try:
                found[agent] = [shlex.join(json.loads(m.group(1)))] if m else []
            except ValueError:
                found[agent] = []
    hooks_dir = _git_hooks_dir(project)
    if hooks_dir:
        cmds = [line for kind in ("pre-commit", "pre-push") if (t := _read(hooks_dir / kind)) and
                "agent-ledger-git-hook" in t and (line := _exec_line(t))]
        if cmds:
            found["git"] = cmds
    return found


def _git_hooks_dir(project: Path) -> Path | None:
    if not (project / ".git").exists():
        return None
    try:
        r = subprocess.run(["git", "-c", "core.fsmonitor=false", "rev-parse", "--git-path", "hooks"], cwd=project,
                           capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return (project / r.stdout.strip()) if r.returncode == 0 and r.stdout.strip() else None


def _missing_program(cmd: str) -> str | None:
    """The program a hook command runs, if it can't be found."""
    try:
        prog = shlex.split(cmd)[0]
    except (ValueError, IndexError):
        return cmd
    if os.path.isabs(prog):
        return None if os.path.isfile(prog) and os.access(prog, os.X_OK) else prog
    return None if shutil.which(prog) else prog


def _inside(path: str | None, project: str) -> bool:
    if not path:
        return False
    try:
        p = os.path.realpath(path)
    except (OSError, ValueError):
        return False
    return p == project or p.startswith(project.rstrip(os.sep) + os.sep)


def _activity(db: Path, project: Path) -> dict[str, dict]:
    """agent -> {"sessions", "last"} for sessions whose working directory is inside the project."""
    if not db.is_file():
        return {}
    proj = os.path.realpath(project)
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            rows = conn.execute("SELECT agent, cwd, last_event_at FROM sessions").fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return {}
    out: dict[str, dict] = {}
    for agent, cwd, last in rows:
        if _inside(cwd, proj):
            a = out.setdefault(agent, {"sessions": 0, "last": None})
            a["sessions"] += 1
            a["last"] = max(filter(None, (a["last"], last)), default=None)
    return out


def check(project: Path, env) -> dict:
    project = Path(project).resolve()
    cfg = load_config(env)
    home = ledger_home(env)
    activity = _activity(cfg.db_path, project)
    agents = []
    for agent, cmds in sorted(detect(project).items()):
        a = {"agent": agent, "status": "ok", "message": "", "hint": None}
        missing = sorted({m for c in cmds if (m := _missing_program(c))})
        seen = activity.get(agent)
        if missing:
            a.update(status="fail", message=f"hook command not found: {', '.join(missing)}. The agent runs ungoverned.",
                     hint=f"Re-run `agent-ledger init --agent {agent}` from the agent-ledger you use.")
        elif not cmds:
            a.update(status="fail", message="set up, but its hook command can't be read.",
                     hint=f"Re-run `agent-ledger init --agent {agent}`.")
        elif not seen and agent == "git":
            a.update(status="warn", message="hooks installed, but no commit or push has gone through them yet.",
                     hint=HINTS["git"])
        elif not seen:
            a.update(status="warn",
                     message=f"hooks installed, but no events recorded yet from {agent} in this project. If you've used "
                             f"{agent} here since setting it up, it ran ungoverned.",
                     hint=HINTS.get(agent, f"Start {agent} in this project and make one tool call, then run doctor again."))
        else:
            last = str(seen["last"] or "")[:19].replace("T", " ")
            a["message"] = f"governed: {seen['sessions']} session(s), last event {last} UTC."
        agents.append(a)

    notes = []
    policy = project / ".agent-ledger.toml"
    if policy.is_file():
        from agent_ledger.policyfile import is_trusted, sha256

        if not is_trusted(policy, sha256(policy.read_bytes()), home):
            notes.append({"status": "fail", "message": f"{policy.name} has changed since it was trusted, so it is not "
                          "trusted: the hook ignores it and uses the built-in starter policy.",
                          "hint": "Review it, then run `agent-ledger policy trust`."})
        else:
            notes.append({"status": "ok", "message": f"{policy.name} is trusted and in force."})
    else:
        notes.append({"status": "ok", "message": "No project policy: the built-in starter policy is in force."})
    errors = home / "errors.log"
    try:
        recent = errors.is_file() and errors.stat().st_size and time.time() - errors.stat().st_mtime < ERRORS_RECENT_S
    except OSError:
        recent = False
    if recent:
        notes.append({"status": "warn", "message": f"Hook errors were logged in the last 24 hours ({errors}). "
                      "Hooks fail open, so those calls may have run ungoverned.",
                      "hint": f"Read {errors}."})
    ok = bool(agents) and all(x["status"] == "ok" for x in agents + notes)
    return {"project": str(project), "ok": ok, "agents": agents, "notes": notes}


_MARK = {"ok": "ok  ", "warn": "WARN", "fail": "FAIL"}


def run_doctor(project, env=None, out=None, as_json: bool = False) -> int:
    import sys

    env = os.environ if env is None else env
    out = out or sys.stdout
    report = check(Path(project), env)
    if as_json:
        out.write(json.dumps(report, indent=2) + "\n")
        return 0 if report["ok"] else 1
    out.write(f"agent-ledger doctor: {report['project']}\n\n")
    if not report["agents"]:
        out.write("No agent is set up in this project. Run `agent-ledger init --agent <name>` "
                  "(see docs/agents.md for the list).\n")
    for a in report["agents"]:
        out.write(f"  {_MARK[a['status']]}  {a['agent']}: {a['message']}\n")
        if a["hint"]:
            out.write(f"        -> {a['hint']}\n")
    out.write("\n")
    for n in report["notes"]:
        out.write(f"  {_MARK[n['status']]}  {n['message']}\n")
        if n.get("hint"):
            out.write(f"        -> {n['hint']}\n")
    out.write("\nAll agents are governed.\n" if report["ok"] else "\nSome agents need attention (see above).\n")
    return 0 if report["ok"] else 1
