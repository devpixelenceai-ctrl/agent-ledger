"""Git-hook fallback for agents without a hook system of their own (Aider, Warp, Zed's agent,
scripts): `.git/hooks/pre-commit` and `pre-push` run `agent-ledger git-hook <kind>`.

Each hook turns what git is about to do into the equivalent shell command (`git commit`,
`git push [--force] <remote> <src>:<dst>`) and runs it through the normal hook pipeline, so the
same policy decides, and the decision is recorded in the ledger as agent "git".

- pre-commit blocks on "ask" or "deny": the starter policy asks only when the staged content
  looks like a secret, and a person can override a false positive with `git commit --no-verify`.
- pre-push blocks only on "deny" (such as a force-push to a protected branch). People push through
  the same hook, and the starter policy asks for every push, so an "ask" is recorded, not blocked.

Like the agent hooks, a crash here never blocks git (unless fail-closed is configured).
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys

ZERO = "0" * 40
_BLOCK_ON = {"pre-commit": ("ask", "deny"), "pre-push": ("deny",)}


def _is_ancestor(old: str, new: str) -> bool:
    try:
        r = subprocess.run(["git", "-c", "core.fsmonitor=false", "merge-base", "--is-ancestor", old, new],
                           capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


def _short(ref: str) -> str:
    return ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else ref


def _payload(kind: str, args: list[str], stdin) -> list[dict]:
    """One canonical PreToolUse payload per thing git is about to do."""
    cwd = os.getcwd()
    base = {"hook_event_name": "PreToolUse", "session_id": f"git-{kind}", "cwd": cwd, "tool_name": "Bash"}
    if kind == "pre-commit":
        return [{**base, "tool_input": {"command": "git commit"}}]
    remote = args[0] if args else "origin"
    out = []
    for line in stdin.read().splitlines():
        parts = line.split()
        if len(parts) != 4:
            continue
        local_ref, local_sha, remote_ref, remote_sha = parts
        if local_sha == ZERO:
            cmd = f"git push {remote} --delete {_short(remote_ref)}"
        else:
            force = remote_sha != ZERO and not _is_ancestor(remote_sha, local_sha)
            cmd = f"git push {'--force ' if force else ''}{remote} {_short(local_ref)}:{_short(remote_ref)}"
        out.append({**base, "tool_input": {"command": cmd}})
    return out


def main(argv: list[str] | None = None, stdin=None, stderr=None, env=None) -> int:
    from agent_ledger.hook import main as hook_main

    argv = sys.argv[1:] if argv is None else argv
    stdin, stderr = stdin or sys.stdin, stderr or sys.stderr
    env = os.environ if env is None else env
    kind = argv[0] if argv else ""
    if kind not in _BLOCK_ON:
        stderr.write("usage: agent-ledger git-hook {pre-commit|pre-push} [git hook arguments]\n")
        return 0
    try:
        payloads = _payload(kind, argv[1:], stdin)
    except Exception:
        from agent_ledger.hook import _tb, log_error

        log_error(env, f"git-hook {kind} error:\n" + _tb())
        return 0
    status = 0
    for data in payloads:
        out, err = io.StringIO(), io.StringIO()
        code = hook_main(io.StringIO(json.dumps(data)), out, err, env, agent="git")
        if code == 2:  # fail-closed: agent-ledger itself failed
            stderr.write(err.getvalue())
            return 1
        try:
            hso = json.loads(out.getvalue() or "{}").get("hookSpecificOutput", {})
        except ValueError:
            hso = {}
        if hso.get("permissionDecision") in _BLOCK_ON[kind]:
            stderr.write(f"{hso.get('permissionDecisionReason')}\n")
            status = 1
    if status:
        stderr.write(f"agent-ledger: {kind} blocked. If this is a false positive and you are a person, "
                     f"re-run the git command with --no-verify.\n")
    return status
