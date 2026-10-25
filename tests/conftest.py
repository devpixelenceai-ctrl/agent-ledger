import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def ledger_home(tmp_path, monkeypatch):
    """Isolated AGENT_LEDGER_HOME so tests never touch ~/.agent-ledger."""
    home = tmp_path / "ledger-home"
    monkeypatch.setenv("AGENT_LEDGER_HOME", str(home))
    monkeypatch.delenv("AGENT_LEDGER_DB", raising=False)
    monkeypatch.delenv("AGENT_LEDGER_HMAC_KEY", raising=False)
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    return home


@pytest.fixture
def project(tmp_path):
    p = tmp_path / "proj"
    p.mkdir()
    return p


def payload(name: str, **overrides) -> dict:
    data = json.loads((FIXTURES / "hook_payloads" / f"{name}.json").read_text())
    data.update(overrides)
    return data


def run_hook(data: dict | str, env: dict | None = None, timeout: float = 10.0):
    """Run the real `agent-ledger hook` entry point in a subprocess."""
    stdin = data if isinstance(data, str) else json.dumps(data)
    full_env = {**os.environ, **(env or {})}
    return subprocess.run(
        [sys.executable, "-m", "agent_ledger", "hook"],
        input=stdin,
        capture_output=True,
        text=True,
        env=full_env,
        timeout=timeout,
    )
