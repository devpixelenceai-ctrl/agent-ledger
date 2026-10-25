import json

from agent_ledger.adapters import claude_code as cc
from agent_ledger.model import Decision
from conftest import payload


def test_to_event_fields():
    ev = cc.to_event(payload("pre_bash"), env={})
    assert ev.agent == "claude-code"
    assert ev.event_type == "PreToolUse" and ev.tool_name == "Bash" and ev.tool_use_id == "toolu_1"
    assert ev.session_id == "sess-0001" and ev.cwd == "/tmp/proj" and ev.project_dir == "/tmp/proj"


def test_project_dir_prefers_env():
    ev = cc.to_event(payload("pre_bash"), env={"CLAUDE_PROJECT_DIR": "/repo"})
    assert ev.project_dir == "/repo"


def test_summaries():
    assert cc.summarize(payload("pre_bash")) == "Bash: pytest -q"
    assert cc.summarize(payload("pre_edit")) == "Edit: /tmp/proj/app.py"
    assert cc.summarize(payload("pre_webfetch")) == "WebFetch: https://example.com/a"
    assert cc.summarize(payload("prompt")).startswith("Prompt: Add a factorial")
    assert cc.summarize(payload("session_start")) == "Session start (startup)"
    assert cc.summarize(payload("session_end")) == "Session end (prompt_input_exit)"
    assert cc.summarize(payload("pre_mcp")) == "mcp__github__create_issue"


def test_summary_is_single_line_and_capped():
    p = payload("pre_bash")
    p["tool_input"]["command"] = "echo a\n" + "x" * 1000
    s = cc.summarize(p)
    assert "\n" not in s and len(s) <= 200


def test_stored_payload_drops_common_fields_and_read_content():
    out = cc.stored_payload(payload("post_read"), max_chars=1000)
    assert "session_id" not in out and "transcript_path" not in out and "hook_event_name" not in out
    assert "x = 2" not in json.dumps(out)
    assert out["tool_response"]["file"]["content"].startswith("[omitted")


def test_stored_payload_caps_long_strings():
    p = payload("post_bash")
    p["tool_response"]["stdout"] = "y" * 5000
    out = cc.stored_payload(p, max_chars=100)
    assert len(out["tool_response"]["stdout"]) < 200 and "truncated" in out["tool_response"]["stdout"]


def test_stored_payload_truncation_does_not_leave_secret_prefix():
    p = payload("post_bash")
    p["tool_response"]["stdout"] = "a" * 90 + " sk-ant-api03-Qm7vX2pL9sR4tY8wK1nB6cF3hJ0dZ5gA"
    out = cc.stored_payload(p, max_chars=100)
    assert "sk-ant" not in json.dumps(out)


def test_stored_payload_is_redacted():
    p = payload("post_bash")
    p["tool_response"]["stdout"] = "GITHUB_TOKEN=ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    assert "ghp_a1B2" not in json.dumps(cc.stored_payload(p, max_chars=1000))


def test_render_none_is_silent():
    assert cc.render(None, "PreToolUse") == ("", 0)


def test_render_pretooluse_decisions():
    for d in ("allow", "deny", "ask"):
        out, code = cc.render(Decision(d, "r1", "high", "because"), "PreToolUse")
        assert code == 0
        obj = json.loads(out)["hookSpecificOutput"]
        assert obj == {
            "hookEventName": "PreToolUse",
            "permissionDecision": d,
            "permissionDecisionReason": "agent-ledger [r1]: because",
        }


def test_render_ignores_decisions_for_other_events():
    assert cc.render(Decision("deny", "r", "high", "x"), "PostToolUse") == ("", 0)
