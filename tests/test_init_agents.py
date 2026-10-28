"""`agent-ledger init --agent <name>` writes each agent's own hook configuration. The strongest test
here takes the command each config registers and runs it, through a shell, with that agent's payload."""

import json
import os
import shutil
import subprocess
import sys

import pytest

from agent_ledger.agent_configs import CONFIGS, install_agent
from agent_ledger.init import InitError
from test_agents import shell

HOOK = [sys.executable, "-m", "agent_ledger", "hook"]
AGENTS = sorted(CONFIGS)


def registered_commands(agent, project):
    """Every (event, command) the agent will run, read back from what init wrote."""
    spec = CONFIGS[agent]
    out = []
    for path in spec.files(project):
        if spec.kind == "script":
            out += [(path.name, f"sh {path}")]
            continue
        data = json.loads(path.read_text())
        container = data
        for key in spec.wrap:
            container = container[key]
        if spec.kind == "kiro":
            out += [(h["trigger"], h["action"]["command"]) for h in container]
            continue
        for event, entries in container.items():
            for e in entries:
                for h in (e.get("hooks", [e]) if spec.kind == "nested" else [e]):
                    cmd = h.get("command") or h.get("bash")
                    out.append((event, f"sh {cmd}" if cmd.endswith(".sh") else cmd))
    return out


def test_every_hook_agent_can_be_installed():
    from agent_ledger.adapters.agents import PROFILES

    assert set(CONFIGS) == set(PROFILES)


@pytest.mark.parametrize("agent", AGENTS)
def test_install_is_idempotent_and_registers_pre_and_post(agent, project):
    assert install_agent(agent, project, HOOK) is True
    cmds = registered_commands(agent, project)
    assert any("--event pre" in c or c.startswith("sh ") for _, c in cmds)
    assert any("--event post" in c or c.startswith("sh ") for _, c in cmds)
    assert all(f"--agent {agent}" in c for _, c in cmds if not c.startswith("sh "))
    assert install_agent(agent, project, HOOK) is False


@pytest.mark.parametrize("agent", [a for a in AGENTS if CONFIGS[a].kind in ("nested", "flat") and not CONFIGS[a].owned])
def test_existing_settings_and_other_hooks_are_kept(agent, project):
    spec = CONFIGS[agent]
    path = spec.files(project)[0]
    path.parent.mkdir(parents=True, exist_ok=True)
    pre_event = next(e for e, w in spec.events.items() if w == "pre")
    theirs = {"command": "./my-own-lint.sh"} if spec.kind == "flat" else {"matcher": "x", "hooks": [{"type": "command", "command": "./mine.sh"}]}
    data = {"model": "keep-me"}
    container = data
    for key in spec.wrap:
        container = container.setdefault(key, {})
    container[pre_event] = [theirs]
    path.write_text(json.dumps(data))
    install_agent(agent, project, HOOK)
    after = path.read_text()
    assert "keep-me" in after and ("my-own-lint.sh" in after or "mine.sh" in after)
    assert f"--agent {agent}" in after or "agent-ledger-pre.sh" in after  # Auggie runs a wrapper script


@pytest.mark.parametrize("agent", AGENTS)
def test_symlinked_config_is_refused(agent, project, tmp_path):
    path = CONFIGS[agent].files(project)[0]
    path.parent.mkdir(parents=True, exist_ok=True)
    victim = tmp_path / "victim"
    victim.write_text("{}")
    path.symlink_to(victim)
    with pytest.raises(InitError):
        install_agent(agent, project, HOOK)
    assert victim.read_text() == "{}"


@pytest.mark.parametrize("agent", [a for a in AGENTS if CONFIGS[a].owned])
def test_foreign_files_are_never_overwritten(agent, project):
    path = CONFIGS[agent].files(project)[0]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("someone else's hook\n")
    with pytest.raises(InitError):
        install_agent(agent, project, HOOK)
    assert path.read_text() == "someone else's hook\n"


def test_invalid_json_is_refused_untouched(project):
    path = CONFIGS["gemini"].files(project)[0]
    path.parent.mkdir(parents=True)
    path.write_text("{oops")
    with pytest.raises(InitError):
        install_agent("gemini", project, HOOK)
    assert path.read_text() == "{oops"


@pytest.mark.skipif(sys.platform == "win32" or not shutil.which("sh"), reason="runs the registered POSIX command")
@pytest.mark.parametrize("agent", AGENTS)
def test_registered_pre_command_really_blocks(agent, project, tmp_path):
    install_agent(agent, project, HOOK)
    spec = CONFIGS[agent]
    pre = [c for e, c in registered_commands(agent, project)
           if spec.events.get(e) == "pre" or e in ("PreToolUse",) or "--event pre" in c]
    assert pre, registered_commands(agent, project)
    env = {**os.environ, "AGENT_LEDGER_HOME": str(tmp_path / "ledger"), "PYTHONPATH": os.pathsep.join(sys.path)}
    res = subprocess.run(["sh", "-c", pre[0]], input=json.dumps(shell(agent, "rm -rf ~", str(project))),
                         capture_output=True, text=True, cwd=project, env=env, timeout=30)
    blocked = res.returncode == 2 or '"deny"' in res.stdout or '"block"' in res.stdout or '"cancel": true' in res.stdout
    assert blocked, (res.returncode, res.stdout, res.stderr)


def test_own_entries_are_recognised_with_windows_paths():
    from agent_ledger.agent_configs import _is_ours

    assert _is_ours({"command": "C:\\proj\\.augment\\hooks\\agent-ledger-pre.sh"}, "auggie")
    assert _is_ours({"command": "C:\\proj\\.augment\\hooks\\agent-ledger-post.sh"}, "auggie")
    assert not _is_ours({"command": "C:\\proj\\my-hook.sh"}, "auggie")
