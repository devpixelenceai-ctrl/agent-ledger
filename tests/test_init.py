import json

import pytest

from agent_ledger.init import HOOK_EVENTS, InitError, install_hooks, merge_hooks

CMD = "agent-ledger hook"


def ours(settings, event):
    return [
        h for g in settings["hooks"].get(event, []) for h in g["hooks"] if "agent-ledger" in h.get("command", "")
    ]


def test_merge_into_empty():
    s, changed = merge_hooks({}, CMD)
    assert changed
    for ev in HOOK_EVENTS:
        assert len(ours(s, ev)) == 1
        assert ours(s, ev)[0]["timeout"] == 10
    assert s["hooks"]["PreToolUse"][0]["matcher"] == "*"


def test_merge_preserves_other_settings_and_hooks():
    existing = {
        "model": "opus",
        "permissions": {"allow": ["Bash(ls)"]},
        "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "my-linter"}]}]},
    }
    s, _ = merge_hooks(json.loads(json.dumps(existing)), CMD)
    assert s["model"] == "opus" and s["permissions"] == existing["permissions"]
    cmds = [h["command"] for g in s["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert "my-linter" in cmds and CMD in cmds


def test_idempotent():
    s, _ = merge_hooks({}, CMD)
    s2, changed = merge_hooks(json.loads(json.dumps(s)), CMD)
    assert not changed and s2 == s


def test_updates_our_old_command_without_duplicating():
    s, _ = merge_hooks({}, "/old/path/agent-ledger hook")
    s2, changed = merge_hooks(s, CMD)
    assert changed
    for ev in HOOK_EVENTS:
        assert [h["command"] for h in ours(s2, ev)] == [CMD]


def test_fail_closed_sets_on_failure_block_on_pretooluse_only():
    s, _ = merge_hooks({}, CMD, fail_closed=True)
    assert ours(s, "PreToolUse")[0]["onFailure"] == "block"
    assert "onFailure" not in ours(s, "PostToolUse")[0]


def test_install_writes_file_and_backup(tmp_path):
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"model": "x"}))
    install_hooks(settings, CMD)
    data = json.loads(settings.read_text())
    assert data["model"] == "x" and "hooks" in data
    assert json.loads((tmp_path / ".claude" / "settings.json.bak").read_text()) == {"model": "x"}


def test_install_creates_missing_file(tmp_path):
    settings = tmp_path / ".claude" / "settings.json"
    install_hooks(settings, CMD)
    assert "PreToolUse" in json.loads(settings.read_text())["hooks"]


def test_install_refuses_invalid_json_and_leaves_file_alone(tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text("{ invalid")
    with pytest.raises(InitError):
        install_hooks(settings, CMD)
    assert settings.read_text() == "{ invalid"


def test_install_refuses_non_object_hooks(tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"hooks": []}))
    with pytest.raises(InitError):
        install_hooks(settings, CMD)
