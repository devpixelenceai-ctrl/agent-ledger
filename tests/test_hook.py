import io
import json
import sqlite3

import pytest

from agent_ledger import hook, store
from agent_ledger.model import Decision
from conftest import payload, run_hook


def call(data, env, monkeypatch=None):
    stdin = io.StringIO(data if isinstance(data, str) else json.dumps(data))
    out, err = io.StringIO(), io.StringIO()
    code = hook.main(stdin=stdin, stdout=out, stderr=err, env=env)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def env(ledger_home):
    return {"AGENT_LEDGER_HOME": str(ledger_home)}


def fail_closed(ledger_home):
    ledger_home.mkdir(parents=True, exist_ok=True)
    (ledger_home / "config.toml").write_text('[ledger]\nfail_mode = "closed"\n')


def events(ledger_home):
    conn = store.connect(ledger_home / "ledger.db")
    return [dict(r) for r in conn.execute("SELECT * FROM events ORDER BY seq")]


def test_records_every_event_type_and_chain_verifies(env, ledger_home):
    names = ["session_start", "prompt", "pre_bash", "post_bash", "pre_read", "post_read", "post_fail",
             "pre_mcp", "permission_request", "stop", "session_end"]
    for n in names:
        code, out, _ = call(payload(n), env)
        assert code == 0
        if out:
            json.loads(out)  # a decision or a systemMessage, never stray text
    rows = events(ledger_home)
    assert [r["event_type"] for r in rows] == [payload(n)["hook_event_name"] for n in names]
    assert store.verify(store.connect(ledger_home / "ledger.db")).ok


def test_decision_is_emitted_and_recorded(env, ledger_home, monkeypatch):
    monkeypatch.setattr(hook, "evaluate", lambda ev, cfg: Decision("deny", "r.x", "critical", "nope", "pol"))
    code, out, _ = call(payload("pre_bash"), env)
    assert code == 0
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    r = events(ledger_home)[-1]
    assert (r["decision"], r["rule_id"], r["severity"], r["policy_hash"]) == ("deny", "r.x", "critical", "pol")


def boom(*a, **k):
    raise RuntimeError("injected failure")


def test_crash_fail_open_is_silent_and_logged(env, ledger_home, monkeypatch):
    monkeypatch.setattr(hook, "evaluate", boom)
    code, out, err = call(payload("pre_bash"), env)
    assert (code, out) == (0, "")
    assert "injected failure" in (ledger_home / "errors.log").read_text()


def test_crash_fail_closed_blocks_pretooluse(env, ledger_home, monkeypatch):
    fail_closed(ledger_home)
    monkeypatch.setattr(hook, "evaluate", boom)
    code, out, err = call(payload("pre_bash"), env)
    assert code == 2 and out == "" and "agent-ledger" in err


def test_crash_fail_closed_never_blocks_other_events(env, ledger_home, monkeypatch):
    fail_closed(ledger_home)
    monkeypatch.setattr(hook.adapter, "to_event", boom)
    for n in ("post_bash", "session_start", "stop", "session_end", "prompt"):
        code, out, _ = call(payload(n), env)
        assert (code, out) == (0, "")


def test_crash_still_records_error_event(env, ledger_home, monkeypatch):
    monkeypatch.setattr(hook, "evaluate", boom)
    call(payload("pre_bash"), env)
    r = events(ledger_home)[-1]
    assert r["decision"] == "error" and "RuntimeError" in r["reason"]


def test_invalid_json(env, ledger_home):
    assert call("{not json", env)[0] == 0
    fail_closed(ledger_home)
    code, out, err = call("{not json", env)
    assert code == 2 and out == ""


def test_record_failure_keeps_policy_decision(env, ledger_home, monkeypatch):
    monkeypatch.setattr(hook, "evaluate", lambda ev, cfg: Decision("deny", "r", "high", "x", "p"))
    monkeypatch.setattr(hook.store, "append", boom)
    code, out, _ = call(payload("pre_bash"), env)
    assert code == 0 and json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_record_failure_fail_closed_blocks_even_allowed_call(env, ledger_home, monkeypatch):
    fail_closed(ledger_home)
    monkeypatch.setattr(hook, "evaluate", lambda ev, cfg: Decision("allow", "r", "info", "x", "p"))
    monkeypatch.setattr(hook.store, "append", boom)
    code, out, _ = call(payload("pre_bash"), env)
    assert code == 2 and out == ""


def test_secrets_never_reach_the_database_file(env, ledger_home):
    secret = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"
    p = payload("post_bash")
    p["tool_input"]["command"] = f"export GITHUB_TOKEN={secret} && gh auth status"
    p["tool_response"]["stdout"] = f"token: {secret}"
    call(p, env)
    call({**payload("prompt"), "prompt": f"here is my key {secret}"}, env)
    for f in ledger_home.iterdir():
        assert secret.encode() not in f.read_bytes(), f"secret leaked into {f.name}"
        assert secret[4:20].encode() not in f.read_bytes()


def test_session_start_captures_git(env, ledger_home, tmp_path):
    repo = tmp_path / "r"
    (repo / ".git" / "refs" / "heads").mkdir(parents=True)
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/feat\n")
    (repo / ".git" / "refs" / "heads" / "feat").write_text("deadbeef\n")
    call({**payload("session_start"), "cwd": str(repo)}, env)
    s = store.get_session(store.connect(ledger_home / "ledger.db"), "sess-0001")
    assert s["git_branch"] == "feat" and s["git_commit"] == "deadbeef" and s["cwd"] == str(repo)


def test_tty_stdin_does_not_hang(env):
    class Tty(io.StringIO):
        def isatty(self):
            return True

    assert hook.main(stdin=Tty(""), stdout=io.StringIO(), stderr=io.StringIO(), env=env) == 0


# --- real subprocess, real failure (not monkeypatched) ---

def test_subprocess_records(ledger_home):
    res = run_hook(payload("pre_bash"), env={"AGENT_LEDGER_HOME": str(ledger_home)})
    assert res.returncode == 0, res.stderr
    assert len(events(ledger_home)) == 1


def test_subprocess_unwritable_db_fail_open_and_closed(ledger_home, tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    env = {"AGENT_LEDGER_HOME": str(ledger_home), "AGENT_LEDGER_DB": str(blocker / "ledger.db")}
    res = run_hook(payload("pre_bash"), env=env)
    assert res.returncode == 0  # fail open: the policy decision (if any) still stands
    assert res.stdout == "" or json.loads(res.stdout)["hookSpecificOutput"]
    fail_closed(ledger_home)
    res = run_hook(payload("pre_bash"), env=env)
    assert res.returncode == 2 and res.stdout == ""
