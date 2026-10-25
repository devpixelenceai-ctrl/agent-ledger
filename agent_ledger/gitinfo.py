"""Read git branch and commit straight from .git files: no subprocess, so it stays fast."""

from __future__ import annotations

from pathlib import Path

MAX_READ = 4096
MAX_PACKED_REFS = 4_000_000


def _read(path: Path) -> str | None:
    """Read a small regular file. FIFOs, devices and huge files are refused: they could hang the hook."""
    if not path.is_file():
        return None
    with open(path, "rb") as f:
        return f.read(MAX_READ).decode("utf-8", "replace")


def _find_gitdir(start: Path) -> Path | None:
    for d in (start, *start.parents):
        dotgit = d / ".git"
        if dotgit.is_dir():
            return dotgit
        if dotgit.is_file():
            text = (_read(dotgit) or "").strip()
            if not text.startswith("gitdir:"):
                return None
            p = Path(text[len("gitdir:"):].strip())
            return p if p.is_absolute() else (d / p).resolve()
    return None


def _resolve_ref(gitdir: Path, common: Path, ref: str) -> str | None:
    for base in (gitdir, common):
        f = base / ref
        if f.is_file():
            return (_read(f) or "").strip() or None
    packed = common / "packed-refs"
    if packed.is_file() and packed.stat().st_size < MAX_PACKED_REFS:
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
            common = (gitdir / (_read(cd) or ".").strip()).resolve()
        head = _read(gitdir / "HEAD")
        if head is None:
            return None, None
        head = head.strip()
        if head.startswith("ref:"):
            ref = head[4:].strip()
            branch = ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else ref
            return branch, _resolve_ref(gitdir, common, ref)
        return None, head or None
    except (OSError, ValueError):
        return None, None
