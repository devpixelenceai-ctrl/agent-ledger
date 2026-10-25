"""Read git branch and commit straight from .git files: no subprocess, so it stays fast."""

from __future__ import annotations

from pathlib import Path


def _find_gitdir(start: Path) -> Path | None:
    for d in (start, *start.parents):
        dotgit = d / ".git"
        if dotgit.is_dir():
            return dotgit
        if dotgit.is_file():
            text = dotgit.read_text("utf-8", "replace").strip()
            if not text.startswith("gitdir:"):
                return None
            p = Path(text[len("gitdir:"):].strip())
            return p if p.is_absolute() else (d / p).resolve()
    return None


def _resolve_ref(gitdir: Path, common: Path, ref: str) -> str | None:
    for base in (gitdir, common):
        f = base / ref
        if f.is_file():
            return f.read_text("utf-8", "replace").strip() or None
    packed = common / "packed-refs"
    if packed.is_file():
        for line in packed.read_text("utf-8", "replace").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == ref:
                return parts[0]
    return None


def git_info(path: str | None) -> tuple[str | None, str | None]:
    """Return (branch, commit) for the repo containing `path`; (None, None) on any problem."""
    if not path:
        return None, None
    try:
        gitdir = _find_gitdir(Path(path))
        if gitdir is None:
            return None, None
        common = gitdir
        cd = gitdir / "commondir"
        if cd.is_file():
            common = (gitdir / cd.read_text("utf-8").strip()).resolve()
        head = (gitdir / "HEAD").read_text("utf-8", "replace").strip()
        if head.startswith("ref:"):
            ref = head[4:].strip()
            branch = ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else ref
            return branch, _resolve_ref(gitdir, common, ref)
        return None, head or None
    except (OSError, ValueError):
        return None, None
