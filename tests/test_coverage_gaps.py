"""Tests written from the coverage report: fail-safe and edge paths that the suite never exercised."""

import shutil
import subprocess

import pytest

from agent_ledger.config import load_config


# ---------------------------------------------------------------- config: every bad input falls back safely

def test_invalid_config_toml_falls_back_to_defaults(tmp_path):
    (tmp_path / "config.toml").write_text("this is = not [valid toml")
    cfg = load_config({"AGENT_LEDGER_HOME": str(tmp_path)})
    assert cfg.fail_mode == "open" and cfg.db_path == tmp_path / "ledger.db"
    assert any("invalid" in w for w in cfg.warnings)


def test_unknown_fail_mode_falls_back_to_open(tmp_path):
    (tmp_path / "config.toml").write_text('[ledger]\nfail_mode = "sideways"\n')
    cfg = load_config({"AGENT_LEDGER_HOME": str(tmp_path)})
    assert cfg.fail_mode == "open" and any("unknown fail_mode" in w for w in cfg.warnings)


def test_env_overrides_config_file(tmp_path):
    (tmp_path / "config.toml").write_text('[ledger]\nfail_mode = "open"\n')
    cfg = load_config({"AGENT_LEDGER_HOME": str(tmp_path), "AGENT_LEDGER_FAIL_MODE": "closed",
                       "AGENT_LEDGER_DB": str(tmp_path / "other.db")})
    assert cfg.fail_closed and cfg.db_path == tmp_path / "other.db"


def test_bad_max_field_chars_uses_default(tmp_path):
    (tmp_path / "config.toml").write_text('[ledger]\nmax_field_chars = "lots"\n')
    assert load_config({"AGENT_LEDGER_HOME": str(tmp_path)}).max_field_chars == 65536


def test_hmac_key_file_is_read_and_missing_file_warns(tmp_path):
    keyfile = tmp_path / "k"
    keyfile.write_text("s3cret-key\n")
    # TOML literal strings ('...') so Windows backslashes are not read as escapes
    (tmp_path / "config.toml").write_text(f"[ledger]\nhmac_key_file = '{keyfile}'\n")
    assert load_config({"AGENT_LEDGER_HOME": str(tmp_path)}).hmac_key == b"s3cret-key"
    (tmp_path / "config.toml").write_text(f"[ledger]\nhmac_key_file = '{tmp_path / 'missing'}'\n")
    cfg = load_config({"AGENT_LEDGER_HOME": str(tmp_path)})
    assert cfg.hmac_key is None and any("hmac_key_file" in w for w in cfg.warnings)


def test_env_hmac_key_wins(tmp_path):
    assert load_config({"AGENT_LEDGER_HOME": str(tmp_path), "AGENT_LEDGER_HMAC_KEY": "abc"}).hmac_key == b"abc"


# ---------------------------------------------------------------- secretscan: commit option parsing and file limits

from agent_ledger import secretscan  # noqa: E402
from agent_ledger.secretscan import _commit_paths_and_all, scan_git_command  # noqa: E402

GH = "ghp_" + "Zq8Lm2Xv7Rp4Ws9Ky1Nb6Cf3Hj0Dz5Ga1B2c"


@pytest.mark.parametrize("args,paths,all_flag", [
    (["-m", "msg"], [], False),
    (["-am", "msg"], [], True),
    (["-a", "-m", "msg"], [], True),
    (["--all", "--message", "msg"], [], True),
    (["--message=msg", "src/a.py"], ["src/a.py"], False),
    (["-F", "notes.txt", "src/a.py"], ["src/a.py"], False),      # -F's value is a file of the message, not a pathspec
    (["-mmsg", "x.py"], ["x.py"], False),                          # attached value
    (["--author", "A <a@b>", "--", "-weird-name.py"], ["-weird-name.py"], False),
    (["-v", "--no-verify", "-m", "m"], [], False),
])
def test_commit_argument_parsing(args, paths, all_flag):
    assert _commit_paths_and_all(args) == (paths, all_flag)


git_required = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    run = lambda *a: subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *a], cwd=r, check=True,  # noqa: E731
                                    capture_output=True)
    run("init", "-q")
    (r / "a.py").write_text("x = 1\n")
    run("add", "a.py")
    run("commit", "-q", "-m", "init")
    return r


@git_required
def test_add_without_paths_scans_nothing(repo):
    (repo / "s.py").write_text(f"T = '{GH}'\n")
    assert scan_git_command(["git", "add"], str(repo)) == []


@git_required
def test_add_update_ignores_untracked_files(repo):
    (repo / "new.py").write_text(f"T = '{GH}'\n")
    assert scan_git_command(["git", "add", "-u"], str(repo)) == []
    (repo / "a.py").write_text(f"x = 1\nT = '{GH}'\n")
    assert scan_git_command(["git", "add", "-u"], str(repo))


@git_required
def test_huge_binary_and_symlinked_files_are_not_read(repo, tmp_path, monkeypatch):
    monkeypatch.setattr(secretscan, "MAX_FILE_BYTES", 1024)
    (repo / "big.txt").write_text(("pad " * 400) + f"T = '{GH}'\n")
    (repo / "bin.dat").write_bytes(b"\0\1\2" + f"T = '{GH}'".encode())
    outside = tmp_path / "outside-secret.txt"
    outside.write_text(f"T = '{GH}'\n")
    (repo / "link.txt").symlink_to(outside)
    assert scan_git_command(["git", "add", "-A"], str(repo)) == []


@git_required
def test_too_many_files_makes_the_scan_incomplete(repo, monkeypatch):
    monkeypatch.setattr(secretscan, "MAX_FILES", 3)
    for i in range(5):
        (repo / f"f{i}.py").write_text(f"v = {i}\n")
    with pytest.raises(secretscan.ScanIncomplete):
        scan_git_command(["git", "add", "-A"], str(repo))


@git_required
def test_commit_in_repo_without_head_does_not_crash(tmp_path):
    r = tmp_path / "fresh"
    r.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=r, check=True)
    (r / "s.py").write_text(f"T = '{GH}'\n")
    subprocess.run(["git", "add", "s.py"], cwd=r, check=True)
    assert scan_git_command(["git", "commit", "-m", "first"], str(r))   # staged secret found even with no HEAD


def test_not_add_or_commit_is_ignored(tmp_path):
    assert scan_git_command(["git", "status"], str(tmp_path)) == []
    assert scan_git_command(["ls"], str(tmp_path)) == []


# ---------------------------------------------------------------- dashboard diff rendering

from agent_ledger.server import DIFF_MAX_LINES, _diff  # noqa: E402


def test_diff_for_each_file_tool():
    multi = _diff("MultiEdit", {"file_path": "a.py", "edits": [{"old_string": "a", "new_string": "b"},
                                                              {"old_string": "c", "new_string": "d"}]})
    assert "-a" in multi and "+d" in multi
    write = _diff("Write", {"file_path": "n.py", "content": "x\ny"})
    assert write[0] == "+++ n.py" and "+y" in write
    nb = _diff("NotebookEdit", {"notebook_path": "n.ipynb", "new_source": "print(1)"})
    assert "+print(1)" in nb
    assert _diff("Bash", {"command": "ls"}) is None


def test_diff_is_truncated():
    d = _diff("Write", {"file_path": "big.py", "content": "\n".join(str(i) for i in range(DIFF_MAX_LINES * 2))})
    assert len(d) == DIFF_MAX_LINES + 1 and d[-1].startswith("…")
