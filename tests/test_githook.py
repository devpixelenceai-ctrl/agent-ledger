"""Git-hook fallback: governs commits and pushes made by agents that have no hook system of their
own (Aider, Warp, Zed's agent, scripts). Runs as .git/hooks/pre-commit and pre-push."""

import io
import os
import shutil
import sqlite3
import stat
import subprocess
import sys

import pytest

from agent_ledger.githook import main as githook_main
from agent_ledger.init import InitError, install_git_hooks

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

AWS = "AKIAQZ7XK3M9TB2PLW4R"


def git(repo, *args, check=True, env=None):
    return subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *args], cwd=repo,
                          capture_output=True, text=True, check=check, env=env)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    (r / "app.py").write_text("print('hello')\n")
    git(r, "add", "app.py")
    git(r, "commit", "-q", "-m", "init")
    return r


def rows(home):
    db = sqlite3.connect(home / "ledger.db")
    try:
        return db.execute("SELECT agent, event_type, tool_name, decision FROM events ORDER BY seq").fetchall()
    finally:
        db.close()


def run(kind, repo, stdin="", args=()):
    err = io.StringIO()
    cwd = os.getcwd()
    os.chdir(repo)
    try:
        code = githook_main([kind, *args], stdin=io.StringIO(stdin), stderr=err, env=dict(os.environ))
    finally:
        os.chdir(cwd)
    return code, err.getvalue()


# ---------------------------------------------------------------- pre-commit

def test_pre_commit_blocks_staged_secret_and_records_it(repo, ledger_home):
    (repo / "settings.py").write_text(f"aws_key = '{AWS}'\n")
    git(repo, "add", "settings.py")
    code, err = run("pre-commit", repo)
    assert code == 1
    assert "settings.py" in err and "aws-access-key" in err and AWS not in err
    assert "--no-verify" in err  # tells the human how to override
    assert rows(ledger_home)[-1] == ("git", "PreToolUse", "Bash", "ask")
    assert AWS.encode() not in (ledger_home / "ledger.db").read_bytes()


def test_pre_commit_allows_clean_commit(repo, ledger_home):
    (repo / "b.py").write_text("x = 1\n")
    git(repo, "add", "b.py")
    assert run("pre-commit", repo) == (0, "")
    assert rows(ledger_home)[-1] == ("git", "PreToolUse", "Bash", "allow")


# ---------------------------------------------------------------- pre-push

def _push_line(repo, local_sha, remote_sha, ref="refs/heads/main"):
    return f"{ref} {local_sha} {ref} {remote_sha}\n"


def test_pre_push_blocks_force_push_to_main(repo, ledger_home):
    old = git(repo, "rev-parse", "HEAD").stdout.strip()
    git(repo, "commit", "-q", "--amend", "-m", "rewritten")
    new = git(repo, "rev-parse", "HEAD").stdout.strip()
    code, err = run("pre-push", repo, _push_line(repo, new, old), ["origin", "https://example.com/r.git"])
    assert code == 1 and "force" in err.lower()
    assert rows(ledger_home)[-1][3] == "deny"


def test_pre_push_records_but_does_not_block_ordinary_push(repo, ledger_home):
    old = git(repo, "rev-parse", "HEAD").stdout.strip()
    (repo / "c.py").write_text("y = 2\n")
    git(repo, "add", "c.py")
    git(repo, "commit", "-q", "-m", "more")
    new = git(repo, "rev-parse", "HEAD").stdout.strip()
    code, _ = run("pre-push", repo, _push_line(repo, new, old), ["origin", "https://example.com/r.git"])
    assert code == 0
    assert rows(ledger_home)[-1][3] == "ask"  # people push through this hook too: recorded, not blocked


def test_pre_push_new_branch_is_not_a_force_push(repo, ledger_home):
    new = git(repo, "rev-parse", "HEAD").stdout.strip()
    code, _ = run("pre-push", repo, _push_line(repo, new, "0" * 40, "refs/heads/feature"), ["origin", "x"])
    assert code == 0


def test_hook_crash_never_blocks_git(repo, ledger_home, monkeypatch):
    monkeypatch.setattr("agent_ledger.githook._payload", lambda *a: 1 / 0)
    assert run("pre-commit", repo)[0] == 0


# ---------------------------------------------------------------- install

def test_install_writes_executable_hooks_and_is_idempotent(repo):
    argv = [sys.executable, "-m", "agent_ledger"]
    assert install_git_hooks(repo, argv) is True
    for name in ("pre-commit", "pre-push"):
        p = repo / ".git" / "hooks" / name
        if sys.platform != "win32":  # Windows has no executable bit; git runs hooks through its own sh
            assert p.stat().st_mode & stat.S_IXUSR
        assert "agent-ledger-git-hook" in p.read_text()
    assert install_git_hooks(repo, argv) is False


def test_install_never_overwrites_someone_elses_hook(repo):
    p = repo / ".git" / "hooks" / "pre-commit"
    p.write_text("#!/bin/sh\nmake lint\n")
    with pytest.raises(InitError, match="pre-commit"):
        install_git_hooks(repo, [sys.executable, "-m", "agent_ledger"])
    assert p.read_text() == "#!/bin/sh\nmake lint\n"


def test_install_refuses_symlinked_hook(repo, tmp_path):
    target = tmp_path / "victim"
    target.write_text("x")
    (repo / ".git" / "hooks" / "pre-push").symlink_to(target)
    with pytest.raises(InitError):
        install_git_hooks(repo, [sys.executable, "-m", "agent_ledger"])
    assert target.read_text() == "x"


def test_install_respects_core_hooks_path(repo):
    git(repo, "config", "core.hooksPath", ".githooks")
    install_git_hooks(repo, [sys.executable, "-m", "agent_ledger"])
    assert (repo / ".githooks" / "pre-commit").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell hook script")
def test_real_git_commit_is_blocked_end_to_end(repo, ledger_home):
    install_git_hooks(repo, [sys.executable, "-m", "agent_ledger"])
    (repo / "keys.py").write_text(f"aws_key = '{AWS}'\n")
    git(repo, "add", "keys.py")
    env = {**os.environ, "AGENT_LEDGER_HOME": str(ledger_home)}
    res = git(repo, "commit", "-m", "add keys", check=False, env=env)
    assert res.returncode != 0 and "aws-access-key" in res.stderr
    assert git(repo, "log", "--oneline", env=env).stdout.count("\n") == 1  # nothing committed
