import shutil
import subprocess

import pytest

from agent_ledger.gitinfo import git_info


def mk(tmp_path, head, refs=None, packed=None):
    g = tmp_path / ".git"
    g.mkdir()
    (g / "HEAD").write_text(head)
    for name, sha in (refs or {}).items():
        p = g / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(sha + "\n")
    if packed:
        (g / "packed-refs").write_text(packed)
    return tmp_path


def test_branch_loose_ref(tmp_path):
    root = mk(tmp_path, "ref: refs/heads/main\n", {"refs/heads/main": "abc123"})
    assert git_info(str(root)) == ("main", "abc123")


def test_branch_from_subdirectory(tmp_path):
    root = mk(tmp_path, "ref: refs/heads/main\n", {"refs/heads/main": "abc123"})
    sub = root / "a" / "b"
    sub.mkdir(parents=True)
    assert git_info(str(sub)) == ("main", "abc123")


def test_packed_ref(tmp_path):
    root = mk(tmp_path, "ref: refs/heads/dev\n", packed="# pack-refs\nfff111 refs/heads/dev\n")
    assert git_info(str(root)) == ("dev", "fff111")


def test_detached_head(tmp_path):
    root = mk(tmp_path, "0123abcd\n")
    assert git_info(str(root)) == (None, "0123abcd")


def test_unborn_branch(tmp_path):
    root = mk(tmp_path, "ref: refs/heads/main\n")
    assert git_info(str(root)) == ("main", None)


def test_worktree_gitfile(tmp_path):
    (tmp_path / "main_repo").mkdir()
    main = mk(tmp_path / "main_repo", "ref: refs/heads/main\n", {"refs/heads/wt": "beef01"})
    wtdir = main / ".git" / "worktrees" / "wt"
    wtdir.mkdir(parents=True)
    (wtdir / "HEAD").write_text("ref: refs/heads/wt\n")
    (wtdir / "commondir").write_text("../..\n")
    wt = tmp_path / "wt"
    wt.mkdir()
    (wt / ".git").write_text(f"gitdir: {wtdir}\n")
    assert git_info(str(wt)) == ("wt", "beef01")


def test_not_a_repo(tmp_path):
    assert git_info(str(tmp_path)) == (None, None)


def test_garbage_never_raises(tmp_path):
    (tmp_path / ".git").write_text("nonsense")
    assert git_info(str(tmp_path)) == (None, None)


@pytest.mark.skipif(not shutil.which("git"), reason="git not installed")
def test_matches_real_git(tmp_path):
    run = lambda *a: subprocess.run(["git", *a], cwd=tmp_path, check=True, capture_output=True, text=True)
    run("init", "-q", "-b", "trunk")
    run("-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "--allow-empty", "-m", "x")
    sha = run("rev-parse", "HEAD").stdout.strip()
    assert git_info(str(tmp_path)) == ("trunk", sha)
