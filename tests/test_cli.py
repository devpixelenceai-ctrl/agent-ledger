import json
import os
import sqlite3
import subprocess
import sys

from conftest import payload, run_hook


def cli(*args, env=None, cwd=None):
    return subprocess.run(
        [sys.executable, "-m", "agent_ledger", *args],
        capture_output=True, text=True, env={**os.environ, **(env or {})}, cwd=cwd,
    )


def test_init_then_hook_then_verify(ledger_home, project):
    env = {"AGENT_LEDGER_HOME": str(ledger_home)}
    r = cli("init", "--project", str(project), env=env)
    assert r.returncode == 0, r.stderr
    settings = json.loads((project / ".claude" / "settings.json").read_text())
    assert settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "agent-ledger hook"

    for n in ("session_start", "pre_bash", "post_bash", "session_end"):
        assert run_hook(payload(n, cwd=str(project)), env=env).returncode == 0

    r = cli("verify", env=env)
    assert r.returncode == 0 and "OK: 4 events" in r.stdout and "Head hash:" in r.stdout

    c = sqlite3.connect(ledger_home / "ledger.db")
    c.execute("UPDATE events SET summary='Bash: ls' WHERE seq=2")
    c.commit()
    c.close()
    r = cli("verify", env=env)
    assert r.returncode == 1 and "BROKEN at seq 2" in r.stdout


def test_init_absolute_command_quotes_interpreter(ledger_home, project):
    r = cli("init", "--project", str(project), "--absolute", env={"AGENT_LEDGER_HOME": str(ledger_home)})
    assert r.returncode == 0
    cmd = json.loads((project / ".claude" / "settings.json").read_text())["hooks"]["Stop"][0]["hooks"][0]["command"]
    assert cmd.endswith("-m agent_ledger hook") and sys.executable in cmd


def test_init_fail_closed_writes_config(ledger_home, project):
    r = cli("init", "--project", str(project), "--fail-closed", env={"AGENT_LEDGER_HOME": str(ledger_home)})
    assert r.returncode == 0
    assert 'fail_mode = "closed"' in (ledger_home / "config.toml").read_text()


def test_init_rejects_broken_settings(ledger_home, project):
    (project / ".claude").mkdir()
    (project / ".claude" / "settings.json").write_text("{oops")
    r = cli("init", "--project", str(project), env={"AGENT_LEDGER_HOME": str(ledger_home)})
    assert r.returncode == 1 and "not valid JSON" in r.stderr


def test_verify_without_db(ledger_home):
    r = cli("verify", env={"AGENT_LEDGER_HOME": str(ledger_home)})
    assert r.returncode == 0 and "No ledger" in r.stdout
