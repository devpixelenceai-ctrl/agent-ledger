"""Scan what `git add` / `git commit` are about to record, for secrets.

Found in the real-world trial: an agent committed a file full of credentials and nothing
stopped it, because local commits are allowed and the file name did not look secret.

Safety: a cloned repo controls its own git config, and some git operations run programs it
configures (fsmonitor, external diff, textconv, clean/smudge filters). This module therefore
never asks git to compare working-tree files. It lists paths from the index (no content
read), reads working files itself, and fetches committed versions from the object store with
`git cat-file` (no filters). `git diff --cached` (index vs HEAD, both from the object store)
runs with external diff and textconv disabled. Every git call has a time limit.

Only imported when a git add/commit is evaluated, so it costs nothing on other tool calls.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import time

from agent_ledger.redact import _ASSIGN, _KNOWN_RE, _PEM, _URL_CREDS, is_secret_key, is_secret_path

MAX_FILES = 2000
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
DEFAULT_TIMEOUT = 2.0
_PLACEHOLDER = re.compile(
    r"example|placeholder|changeme|change_me|change-me|dummy|test|fake|sample|your|xxx|todo|redacted|insert|replace",
    re.I,
)
_GIT_SAFE = ["-c", "core.fsmonitor=false", "-c", "diff.external=", "-c", "core.quotepath=off",
             "-c", "core.untrackedCache=false", "--no-pager"]
_COMMIT_VALUE_SHORT = set("mFCct")
_COMMIT_VALUE_LONG = {"--message", "--file", "--author", "--date", "--template", "--reuse-message",
                      "--reedit-message", "--fixup", "--squash", "--trailer", "--cleanup"}


class ScanIncomplete(Exception):
    """The change was too large or slow to scan within limits."""


# ---------------------------------------------------------------- detection

def _real_value(v: str) -> bool:
    v = v.strip()
    if len(v) < 8 or _PLACEHOLDER.search(v):
        return False
    if v.startswith(("$", "{", "<", "%")) or any(c in v for c in "([{"):
        return False
    return not re.fullmatch(r"[\d.]+|true|false|none|null", v, re.I)


ALLOW_MARKERS = ("agent-ledger:allow-secret", "gitleaks:allow")


def find_secrets(text: str) -> set[str]:
    """Kinds of secret present in `text` (never the values).

    Lines carrying an inline allow marker (`agent-ledger:allow-secret`, or gitleaks' `gitleaks:allow`)
    are skipped, for deliberate fake secrets in test fixtures.
    """
    if any(m in text for m in ALLOW_MARKERS):
        text = "\n".join(ln for ln in text.splitlines() if not any(m in ln for m in ALLOW_MARKERS))
    kinds: set[str] = set()
    for name, rx in _KNOWN_RE:
        for m in rx.finditer(text):
            if not _PLACEHOLDER.search(m.group(0)):
                kinds.add(name)
                break
    if _PEM.search(text):
        kinds.add("private-key")
    for m in _URL_CREDS.finditer(text):
        if _real_value(m.group(3)):
            kinds.add("url-credentials")
            break
    for m in _ASSIGN.finditer(text):
        value = m.group(5) if m.group(4) else m.group(6)
        if value and is_secret_key(m.group(2)) and _real_value(value):
            kinds.add("secret-assignment")
            break
    return kinds


# ---------------------------------------------------------------- git plumbing (no filters, no external programs)

class _Git:
    def __init__(self, cwd: str, timeout: float):
        self.cwd = cwd
        self.deadline = time.monotonic() + timeout

    def remaining(self) -> float:
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise ScanIncomplete("time limit reached")
        return left

    def run(self, *args: str, stdin: bytes | None = None) -> bytes | None:
        env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "GIT_EXTERNAL_DIFF": "",
               "GIT_PAGER": "cat", "LC_ALL": "C"}
        try:
            r = subprocess.run(["git", *_GIT_SAFE, *args], cwd=self.cwd, input=stdin, capture_output=True,
                               timeout=self.remaining(), env=env)
        except subprocess.TimeoutExpired as e:
            raise ScanIncomplete("git timed out") from e
        except OSError:
            return None
        return r.stdout if r.returncode == 0 else None

    def toplevel(self) -> str | None:
        out = self.run("rev-parse", "--show-toplevel")
        return out.decode("utf-8", "replace").strip() if out else None

    def index(self, pathspec: list[str]) -> dict[str, str]:
        out = self.run("ls-files", "-s", "-z", "--", *pathspec) or b""
        entries = {}
        for rec in out.split(b"\0"):
            if b"\t" in rec:
                meta, path = rec.split(b"\t", 1)
                entries[path.decode("utf-8", "replace")] = meta.split()[1].decode()
        return entries

    def untracked(self, pathspec: list[str]) -> list[str]:
        out = self.run("ls-files", "--others", "--exclude-standard", "-z", "--", *pathspec) or b""
        return [p.decode("utf-8", "replace") for p in out.split(b"\0") if p]

    def head_blobs(self, paths: list[str]) -> dict[str, bytes]:
        if not paths:
            return {}
        out = self.run("cat-file", "--batch", stdin=b"".join(f"HEAD:{p}\n".encode() for p in paths)) or b""
        blobs, i = {}, 0
        for p in paths:
            nl = out.find(b"\n", i)
            if nl < 0:
                break
            header = out[i:nl].split()
            i = nl + 1
            if len(header) == 3 and header[1] == b"blob":
                size = int(header[2])
                blobs[p] = out[i:i + size]
                i += size + 1
        return blobs

    def staged_additions(self) -> dict[str, str]:
        out = self.run("diff", "--cached", "-U0", "--no-color", "--no-ext-diff", "--no-textconv",
                       "--diff-filter=ACMR") or b""
        files: dict[str, list[str]] = {}
        current = None
        for line in out.decode("utf-8", "replace").splitlines():
            if line.startswith("+++ "):
                current = line[6:] if line.startswith("+++ b/") else None
                if current is not None:
                    files.setdefault(current, [])
            elif current is not None and line.startswith("+"):
                files[current].append(line[1:])
        return {p: "\n".join(lines) for p, lines in files.items()}


def _blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def _read(top: str, rel: str, budget: list[int]) -> bytes | None:
    path = os.path.join(top, rel)
    try:
        if not os.path.isfile(path) or os.path.islink(path):
            return None
        size = os.path.getsize(path)
        if size > MAX_FILE_BYTES:
            return None
        budget[0] -= size
        if budget[0] < 0:
            raise ScanIncomplete("change too large to scan")
        with open(path, "rb") as f:
            data = f.read(MAX_FILE_BYTES)
    except OSError:
        return None
    return None if b"\0" in data[:8192] else data


def _added_text(new: bytes, old: bytes | None) -> str:
    new_lines = new.decode("utf-8", "replace").splitlines()
    if not old:
        return "\n".join(new_lines)
    old_lines = set(old.decode("utf-8", "replace").splitlines())
    return "\n".join(ln for ln in new_lines if ln not in old_lines)


def _scan_worktree(g: _Git, top: str, pathspec: list[str], include_untracked: bool,
                   findings: list[tuple[str, str]]) -> None:
    index = g.index(pathspec)
    budget = [MAX_TOTAL_BYTES]
    changed: dict[str, bytes] = {}
    for rel, sha in index.items():
        data = _read(top, rel, budget)
        if data is not None and _blob_sha(data) != sha:
            changed[rel] = data
        g.remaining()
    new_files: dict[str, bytes] = {}
    if include_untracked:
        for rel in g.untracked(pathspec)[: MAX_FILES + 1]:
            if is_secret_path(rel):
                findings.append((rel, "secret-file"))
            data = _read(top, rel, budget)
            if data is not None:
                new_files[rel] = data
    if len(changed) + len(new_files) > MAX_FILES:
        raise ScanIncomplete("too many changed files to scan")
    heads = g.head_blobs(list(changed))
    for rel, data in changed.items():
        if is_secret_path(rel):
            findings.append((rel, "secret-file"))
        findings += [(rel, k) for k in sorted(find_secrets(_added_text(data, heads.get(rel))))]
    for rel, data in new_files.items():
        findings += [(rel, k) for k in sorted(find_secrets(_added_text(data, None)))]


def _commit_paths_and_all(args: list[str]) -> tuple[list[str], bool]:
    paths, all_flag, i = [], False, 0
    while i < len(args):
        a = args[i]
        if a == "--":
            paths += args[i + 1:]
            break
        if a.startswith("--"):
            if a in ("--all",):
                all_flag = True
            elif a in _COMMIT_VALUE_LONG:
                i += 1
            i += 1
            continue
        if a.startswith("-") and len(a) > 1:
            for j, ch in enumerate(a[1:]):
                if ch == "a":
                    all_flag = True
                if ch in _COMMIT_VALUE_SHORT:
                    if j == len(a) - 2:
                        i += 1  # value is the next argument
                    break
            i += 1
            continue
        paths.append(a)
        i += 1
    return paths, all_flag


def scan_git_command(argv: list[str], cwd: str, timeout: float = DEFAULT_TIMEOUT) -> list[tuple[str, str]]:
    """Findings (path, kind) for a normalised `git add|commit ...` argv. Raises ScanIncomplete."""
    if len(argv) < 2 or argv[0] != "git" or argv[1] not in ("add", "commit"):
        return []
    g = _Git(cwd, timeout)
    top = g.toplevel()
    if not top:
        return []
    findings: list[tuple[str, str]] = []
    args = argv[2:]
    if argv[1] == "add":
        opts = [a for a in args if a.startswith("-")]
        paths = [a for a in args if not a.startswith("-")]
        whole = any(o in ("-A", "--all", "--no-ignore-removal") for o in opts)
        if not paths and not whole and not any(o in ("-u", "--update") for o in opts):
            return []
        include_untracked = not any(o in ("-u", "--update") for o in opts)
        pathspec = [] if whole and not paths else [os.path.relpath(os.path.join(cwd, p), top) for p in paths]
        g.cwd = top
        _scan_worktree(g, top, pathspec, include_untracked, findings)
    else:
        paths, all_flag = _commit_paths_and_all(args)
        g.cwd = top
        for rel, text in g.staged_additions().items():
            if is_secret_path(rel):
                findings.append((rel, "secret-file"))
            findings += [(rel, k) for k in sorted(find_secrets(text))]
        if all_flag or paths:
            pathspec = [os.path.relpath(os.path.join(cwd, p), top) for p in paths]
            _scan_worktree(g, top, pathspec, include_untracked=False, findings=findings)
    seen, unique = set(), []
    for f in findings:
        if f not in seen:
            seen.add(f)
            unique.append(f)
    return unique
