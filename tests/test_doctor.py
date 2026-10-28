"""`agent-ledger doctor`: is each agent set up in this project really governed?

The live runs showed an agent can have agent-ledger's hooks installed and still run ungoverned
(Codex skips unapproved hooks, Gemini untrusted folders, Cline's "Enable Hooks", Goose plugins).
doctor finds every agent set up in a project and says plainly whether its hooks have ever fired."""

import io
import json
import os
import subprocess
import sys

import pytest

from agent_ledger.agent_configs import install_agent
from agent_ledger.doctor import run_doctor
from agent_ledger.hook import main as hook_main
from agent_ledger.init import install_amp_plugin, install_git_hooks, install_hooks
from agent_ledger.policyfile import STARTER, trust_policy
from test_agents import shell

HOOK = [sys.executable, "-m", "agent_ledger", "hook"]


@pytest.fixture
def proj(tmp_path, ledger_home):
    p = tmp_path / "proj"
    p.mkdir()
    (p / ".agent-ledger.toml").write_text(STARTER.read_text())
    trust_policy(p / ".agent-ledger.toml", ledger_home)
    return p


def doctor(proj, ledger_home):
    out = io.StringIO()
    code = run_doctor(proj, {**os.environ, "AGENT_LEDGER_HOME": str(ledger_home)}, out=out)
    return code, out.getvalue()


def fire(agent, proj, ledger_home, cwd=None):
    """One real hook call from `agent`, as if the agent had made a harmless tool call."""
    data = shell(agent, "ls", str(cwd or proj))
    hook_main(io.StringIO(json.dumps(data)), io.StringIO(), io.StringIO(),
              {"AGENT_LEDGER_HOME": str(ledger_home)}, agent=agent, event="pre")


def test_nothing_set_up(proj, ledger_home):
    code, out = doctor(proj, ledger_home)
    assert code == 1 and "No agent is set up" in out and "agent-ledger init --agent" in out


def test_installed_but_never_fired_says_so_with_the_agents_fix(proj, ledger_home):
    install_agent("codex", proj, HOOK)
    code, out = doctor(proj, ledger_home)
    assert code == 1
    assert "codex" in out and "no events" in out.lower() and "ungoverned" in out
    assert "approve" in out  # Codex's own fix: approve the hooks in Codex


@pytest.mark.parametrize("agent,hint", [("gemini", "trust"), ("cline", "Enable Hooks"), ("goose", "plugin")])
def test_agent_specific_hints(proj, ledger_home, agent, hint):
    install_agent(agent, proj, HOOK)
    assert hint in doctor(proj, ledger_home)[1]


def test_governed_once_a_hook_has_fired(proj, ledger_home):
    install_agent("codex", proj, HOOK)
    fire("codex", proj, ledger_home)
    code, out = doctor(proj, ledger_home)
    assert code == 0, out
    assert "codex" in out and "governed" in out


def test_events_from_a_subdirectory_count(proj, ledger_home):
    install_agent("qwen", proj, HOOK)
    (proj / "src").mkdir()
    fire("qwen", proj, ledger_home, cwd=proj / "src")
    assert doctor(proj, ledger_home)[0] == 0


def test_events_from_another_project_do_not_count(proj, ledger_home, tmp_path):
    install_agent("codex", proj, HOOK)
    other = tmp_path / "other"
    other.mkdir()
    fire("codex", other, ledger_home)
    assert doctor(proj, ledger_home)[0] == 1


def test_missing_hook_command_is_a_failure(proj, ledger_home):
    install_agent("cursor", proj, ["/nonexistent/agent-ledger", "hook"])
    code, out = doctor(proj, ledger_home)
    assert code == 1 and "/nonexistent/agent-ledger" in out and "not found" in out


def test_policy_edited_after_trust_is_flagged(proj, ledger_home):
    install_agent("codex", proj, HOOK)
    fire("codex", proj, ledger_home)
    with open(proj / ".agent-ledger.toml", "a") as f:
        f.write("\n# edited\n")
    code, out = doctor(proj, ledger_home)
    assert code == 1 and "not trusted" in out and "policy trust" in out


def test_no_project_policy_is_reported_but_fine(proj, ledger_home):
    (proj / ".agent-ledger.toml").unlink()
    install_agent("codex", proj, HOOK)
    fire("codex", proj, ledger_home)
    code, out = doctor(proj, ledger_home)
    assert code == 0 and "built-in starter policy" in out


def test_recent_hook_errors_are_surfaced(proj, ledger_home):
    install_agent("codex", proj, HOOK)
    fire("codex", proj, ledger_home)
    (ledger_home / "errors.log").write_text("2026-10-28T00:00:00Z hook input error:\nTraceback ...\n")
    code, out = doctor(proj, ledger_home)
    assert code == 1 and "errors.log" in out


def test_detects_claude_code_plugins_and_git_hooks(proj, ledger_home):
    subprocess.run(["git", "init", "-q"], cwd=proj, check=True)
    install_hooks(proj / ".claude" / "settings.json", "agent-ledger hook")
    install_amp_plugin(proj, HOOK + ["--agent", "amp"])
    install_git_hooks(proj, HOOK[:-1])
    out = doctor(proj, ledger_home)[1]
    for agent in ("claude-code", "amp", "git"):
        assert agent in out


def test_json_output(proj, ledger_home):
    install_agent("codex", proj, HOOK)
    out = io.StringIO()
    code = run_doctor(proj, {**os.environ, "AGENT_LEDGER_HOME": str(ledger_home)}, out=out, as_json=True)
    data = json.loads(out.getvalue())
    assert code == 1 and data["ok"] is False
    assert [a["agent"] for a in data["agents"]] == ["codex"] and data["agents"][0]["status"] == "warn"


def test_cli(proj, ledger_home):
    install_agent("codex", proj, HOOK)
    r = subprocess.run([sys.executable, "-m", "agent_ledger", "doctor", "--project", str(proj)], capture_output=True,
                       text=True, env={**os.environ, "AGENT_LEDGER_HOME": str(ledger_home)}, timeout=60)
    assert r.returncode == 1 and "codex" in r.stdout
