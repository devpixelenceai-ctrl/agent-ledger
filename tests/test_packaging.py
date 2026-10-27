"""End-to-end install test: build the package, install it into a fresh venv (what pipx does),
then `agent-ledger init` in a fresh git repo and drive the installed hook like Claude Code would.

Needs network for the build backend, so it runs only when AGENT_LEDGER_PACKAGING_TEST=1 (CI sets it).
"""

import json
import os
import subprocess
import sys
import venv
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(os.environ.get("AGENT_LEDGER_PACKAGING_TEST") != "1",
                                reason="set AGENT_LEDGER_PACKAGING_TEST=1 to run the install test")


def test_install_init_and_govern_fresh_repo(tmp_path):
    env_dir = tmp_path / "venv"
    venv.create(env_dir, with_pip=True)
    bindir = env_dir / ("Scripts" if os.name == "nt" else "bin")
    py = bindir / "python"
    subprocess.run([str(py), "-m", "pip", "install", "-q", str(ROOT)], check=True)
    exe = bindir / ("agent-ledger.exe" if os.name == "nt" else "agent-ledger")
    assert exe.exists()

    home = tmp_path / "ledger-home"
    repo = tmp_path / "fresh-repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    (repo / ".env").write_text("API_KEY=sk-ant-api03-" + "Zz9" * 20 + "\n")
    env = {**os.environ, "AGENT_LEDGER_HOME": str(home), "CLAUDE_PROJECT_DIR": str(repo)}
    env.pop("PYTHONPATH", None)

    r = subprocess.run([str(exe), "init", "--project", str(repo)], capture_output=True, text=True, env=env, cwd=repo)
    assert r.returncode == 0, r.stderr
    settings = json.loads((repo / ".claude" / "settings.json").read_text())
    assert settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "agent-ledger hook"

    def hook(event: dict) -> subprocess.CompletedProcess:
        base = {"session_id": "e2e", "transcript_path": "/tmp/t", "cwd": str(repo)}
        return subprocess.run([str(exe), "hook"], input=json.dumps({**base, **event}), capture_output=True,
                              text=True, env=env, cwd=repo)

    assert hook({"hook_event_name": "SessionStart", "source": "startup"}).returncode == 0
    deny = hook({"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_use_id": "1",
                 "tool_input": {"file_path": str(repo / ".env")}})
    assert json.loads(deny.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    ask = hook({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_use_id": "2",
                "tool_input": {"command": "git push origin main"}})
    assert json.loads(ask.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert hook({"hook_event_name": "SessionEnd", "reason": "other"}).returncode == 0

    v = subprocess.run([str(exe), "verify"], capture_output=True, text=True, env=env)
    assert v.returncode == 0 and "OK: 4 events" in v.stdout
    out = tmp_path / "report.html"
    rep = subprocess.run([str(exe), "report", "--session", "e2e", "--format", "html", "-o", str(out)],
                         capture_output=True, text=True, env=env)
    assert rep.returncode == 0 and "secrets.files" in out.read_text()
    # the secret from .env never reached the ledger
    for f in home.glob("ledger.db*"):
        assert b"Zz9Zz9Zz9" not in f.read_bytes()
