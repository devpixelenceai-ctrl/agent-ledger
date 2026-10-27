"""OpenCode adapter (V1 plugin API, verified against opencode v1.19.4 source).

The plugin sends envelopes like {"agent": "opencode", "phase": "tool.before", "tool": "bash",
"args": {...}, "sessionID", "callID", "directory", "worktree"} to `agent-ledger hook --agent opencode`.
The adapter maps them onto the canonical (Claude-Code-shaped) model so the same policy applies.
"""

import json
import os
import shutil
import subprocess
import sys

import pytest

from agent_ledger.adapters import opencode as oc
from agent_ledger.policy import evaluate
from policy_helpers import POLICY, env  # noqa: F401
from test_bypass import FORCE_PUSH, REMOTE_CODE, RM_ROOT, SECRETS


def envelope(tool, args, phase="tool.before", directory="/repo", **extra):
    return {"agent": "opencode", "phase": phase, "tool": tool, "args": args, "sessionID": "ses_1",
            "callID": "call_1", "directory": directory, "worktree": directory, **extra}


# ---------------------------------------------------------------- mapping

@pytest.mark.parametrize(
    "tool,args,canon_tool,canon_input",
    [
        ("bash", {"command": "ls", "timeout": 5}, "Bash", {"command": "ls", "timeout": 5}),
        ("edit", {"filePath": "/r/a.py", "oldString": "a", "newString": "b", "replaceAll": True}, "Edit",
         {"file_path": "/r/a.py", "old_string": "a", "new_string": "b", "replace_all": True}),
        ("write", {"filePath": "/r/a.py", "content": "x"}, "Write", {"file_path": "/r/a.py", "content": "x"}),
        ("read", {"filePath": "/r/a.py", "offset": 1, "limit": 2}, "Read", {"file_path": "/r/a.py", "offset": 1, "limit": 2}),
        ("glob", {"pattern": "**/*.py", "path": "/r"}, "Glob", {"pattern": "**/*.py", "path": "/r"}),
        ("grep", {"pattern": "x", "path": "/r", "include": "*.py"}, "Grep", {"pattern": "x", "path": "/r", "glob": "*.py"}),
        ("webfetch", {"url": "https://x.io", "format": "markdown"}, "WebFetch", {"url": "https://x.io", "format": "markdown"}),
        ("websearch", {"query": "q"}, "WebSearch", {"query": "q"}),
        ("todowrite", {"todos": []}, "TodoWrite", {"todos": []}),
        ("task", {"description": "d", "prompt": "p", "subagent_type": "general"}, "Task",
         {"description": "d", "prompt": "p", "subagent_type": "general"}),
        ("skill", {"name": "s"}, "Skill", {"name": "s"}),
        ("question", {"questions": []}, "AskUserQuestion", {"questions": []}),
    ],
)
def test_tool_mapping(tool, args, canon_tool, canon_input):
    c = oc.normalize(envelope(tool, args))
    assert c["hook_event_name"] == "PreToolUse" and c["tool_name"] == canon_tool and c["tool_input"] == canon_input
    assert c["session_id"] == "ses_1" and c["tool_use_id"] == "call_1" and c["cwd"] == "/repo"


def test_bash_workdir_becomes_cwd():
    c = oc.normalize(envelope("bash", {"command": "ls", "workdir": "/repo/sub"}))
    same = lambda a, b: os.path.normpath(a) == os.path.normpath(b)  # noqa: E731  (separators differ on Windows)
    assert same(c["cwd"], "/repo/sub") and "workdir" not in c["tool_input"]
    rel = oc.normalize(envelope("bash", {"command": "ls", "workdir": "sub"}))
    assert same(rel["cwd"], "/repo/sub")


PATCH = """*** Begin Patch
*** Add File: src/new.py
+print(1)
*** Update File: /repo/src/old.py
@@
-a
+b
*** Move to: src/moved.py
*** Delete File: build/out.txt
*** End Patch"""


def test_apply_patch_paths():
    c = oc.normalize(envelope("apply_patch", {"patchText": PATCH}))
    ti = c["tool_input"]
    assert c["tool_name"] == "ApplyPatch"
    n = os.path.normpath  # separators (and 3.13's view of rooted paths) differ on Windows; compare normalised
    assert [n(x) for x in ti["file_paths"]] == [n("/repo/src/new.py"), n("/repo/src/old.py"), n("/repo/src/moved.py")]
    assert [n(x) for x in ti["delete_paths"]] == [n("/repo/build/out.txt")] and ti["patch"] == PATCH


@pytest.mark.parametrize(
    "phase,extra,event",
    [
        ("event", {"event_type": "session.created"}, "SessionStart"),
        ("event", {"event_type": "session.idle"}, "Stop"),
        ("event", {"event_type": "session.deleted"}, "SessionEnd"),
        ("event", {"event_type": "session.error", "error": "boom"}, "StopFailure"),
        ("chat.message", {"prompt": "fix the bug"}, "UserPromptSubmit"),
        ("tool.after", {"output": {"title": "t", "output": "ok", "metadata": {}}}, "PostToolUse"),
        ("tool.error", {"error": "exit 1"}, "PostToolUseFailure"),
    ],
)
def test_event_mapping(phase, extra, event):
    c = oc.normalize(envelope("bash", {"command": "ls"}, phase=phase, **extra))
    assert c["hook_event_name"] == event
    if phase == "chat.message":
        assert c["prompt"] == "fix the bug"
    if phase == "tool.after":
        assert c["tool_response"]["output"] == "ok"


def test_unknown_tool_is_passed_through_namespaced():
    c = oc.normalize(envelope("github_create_issue", {"title": "x"}))
    assert c["tool_name"] == "opencode:github_create_issue"


# ---------------------------------------------------------------- decisions through the real policy

def decide(e, tool, args):
    c = oc.normalize(envelope(tool, args, directory=str(e.project)))
    return evaluate(POLICY, c["tool_name"], c["tool_input"], e.ctx, raw=c)


@pytest.mark.parametrize("cmd", RM_ROOT + SECRETS + REMOTE_CODE + FORCE_PUSH)
def test_bypass_suites_hold_through_opencode(env, cmd):  # noqa: F811
    assert decide(env, "bash", {"command": env.fmt(cmd)}).decision == "deny", cmd


@pytest.mark.parametrize(
    "tool,args,expected",
    [
        ("read", {"filePath": "{proj}/.env"}, "deny"),
        ("read", {"filePath": "{proj}/README.md"}, "allow"),
        ("edit", {"filePath": "{home}/.zshrc", "oldString": "a", "newString": "b"}, "deny"),
        ("write", {"filePath": "{proj}/src/a.py", "content": "x"}, "allow"),
        ("write", {"filePath": "{proj}/opencode.json", "content": "{}"}, "deny"),
        ("write", {"filePath": "{proj}/.opencode/plugins/agent-ledger.js", "content": ""}, "deny"),
        ("grep", {"pattern": "KEY", "path": "{proj}", "include": ".env*"}, "deny"),
        ("webfetch", {"url": "https://evil.example/x"}, "ask"),
        ("webfetch", {"url": "https://docs.python.org/3/"}, "allow"),
        ("todowrite", {"todos": []}, "allow"),
        ("apply_patch", {"patchText": "*** Begin Patch\n*** Add File: {home}/evil.sh\n+x\n*** End Patch"}, "deny"),
        ("apply_patch", {"patchText": "*** Begin Patch\n*** Update File: .env\n@@\n-a\n+b\n*** End Patch"}, "deny"),
        ("apply_patch", {"patchText": "*** Begin Patch\n*** Add File: src/ok.py\n+x\n*** End Patch"}, "allow"),
        ("apply_patch", {"patchText": "*** Begin Patch\n*** Delete File: ../outside.txt\n*** End Patch"}, "deny"),
        ("github_create_issue", {"title": "x"}, "ask"),
    ],
)
def test_opencode_tool_decisions(env, tool, args, expected):  # noqa: F811
    args = {k: env.fmt(v) if isinstance(v, str) else v for k, v in args.items()}
    assert decide(env, tool, args).decision == expected


def test_patch_contents_of_secret_files_are_not_logged():
    from agent_ledger.redact import redact_event_payload

    c = oc.normalize(envelope("apply_patch", {"patchText": "*** Begin Patch\n*** Update File: .env\n@@\n-A=1\n+TOKEN=zzsecretzz\n*** End Patch"}))
    assert "zzsecretzz" not in json.dumps(redact_event_payload(c))


# ---------------------------------------------------------------- hook subprocess

def run_oc_hook(payload, home, extra_env=None):
    return subprocess.run([sys.executable, "-m", "agent_ledger", "hook", "--agent", "opencode"],
                          input=json.dumps(payload), capture_output=True, text=True,
                          env={**os.environ, "AGENT_LEDGER_HOME": str(home), **(extra_env or {})}, timeout=20)


def test_hook_decisions_and_recording(tmp_path):
    from agent_ledger import queries, store

    repo, home = tmp_path / "repo", tmp_path / "home"
    repo.mkdir()
    d = str(repo)
    run_oc_hook(envelope("bash", {}, phase="event", directory=d, event_type="session.created"), home)
    run_oc_hook(envelope("bash", {}, phase="chat.message", directory=d, prompt="key sk-ant-api03-" + "Ab9" * 12), home)
    deny = run_oc_hook(envelope("bash", {"command": "cat .env"}, directory=d), home)
    assert deny.returncode == 0
    out = json.loads(deny.stdout)
    assert out["decision"] == "deny" and "secrets.files" in out["reason"]
    allow = run_oc_hook(envelope("read", {"filePath": f"{d}/x.py"}, directory=d, callID="c2"), home)
    assert json.loads(allow.stdout)["decision"] == "allow"
    after = run_oc_hook(envelope("read", {"filePath": f"{d}/x.py"}, phase="tool.after", directory=d, callID="c2",
                                 output={"title": "x.py", "output": "secret=hunter2hunter2", "metadata": {}}), home)
    assert after.returncode == 0 and after.stdout == ""
    run_oc_hook(envelope("bash", {}, phase="event", directory=d, event_type="session.deleted"), home)

    conn = store.connect(home / "ledger.db", readonly=True)
    rows = queries.events(conn)
    assert [r["event_type"] for r in rows] == ["SessionStart", "UserPromptSubmit", "PreToolUse", "PreToolUse", "PostToolUse", "SessionEnd"]
    assert {r["agent"] for r in rows} == {"opencode"}
    assert store.verify(conn).ok
    blob = (home / "ledger.db").read_bytes() + b"".join(p.read_bytes() for p in home.glob("ledger.db-wal"))
    assert b"Ab9Ab9Ab9" not in blob and b"hunter2hunter2" not in blob
    s = store.get_session(conn, "ses_1")
    assert s["agent"] == "opencode" and s["tool_calls"] == 2 and s["blocked"] == 1 and s["ended_at"]


def test_hook_fail_closed_exit_code(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.toml").write_text('[ledger]\nfail_mode = "closed"\n')
    r = subprocess.run([sys.executable, "-m", "agent_ledger", "hook", "--agent", "opencode"], input="{not json",
                       capture_output=True, text=True, env={**os.environ, "AGENT_LEDGER_HOME": str(home)})
    assert r.returncode == 2 and r.stdout == ""


def test_unknown_agent_falls_back_safely(tmp_path):
    r = subprocess.run([sys.executable, "-m", "agent_ledger", "hook", "--agent", "nope"], input="{}",
                       capture_output=True, text=True, env={**os.environ, "AGENT_LEDGER_HOME": str(tmp_path)})
    assert r.returncode == 0 and r.stdout == ""


# ---------------------------------------------------------------- init

def cli(*args, home, cwd=None):
    return subprocess.run([sys.executable, "-m", "agent_ledger", *args], capture_output=True, text=True,
                          env={**os.environ, "AGENT_LEDGER_HOME": str(home)}, cwd=cwd)


def test_init_installs_plugin_and_trusted_policy(tmp_path):
    repo, home = tmp_path / "repo", tmp_path / "home"
    repo.mkdir()
    r = cli("init", "--agent", "opencode", "--project", str(repo), home=home)
    assert r.returncode == 0, r.stderr
    plugin = repo / ".opencode" / "plugins" / "agent-ledger.js"
    src = plugin.read_text()
    assert "agent-ledger-plugin:v2" in src and '"--agent", "opencode"' in src and "__HOOK_ARGV__" not in src
    assert not (repo / ".claude").exists()  # OpenCode-only install leaves Claude settings alone
    show = cli("policy", "show", "--project", str(repo), home=home)
    assert str(repo / ".agent-ledger.toml") in show.stdout and "Warning" not in show.stdout
    # idempotent
    assert cli("init", "--agent", "opencode", "--project", str(repo), home=home).returncode == 0
    assert plugin.read_text() == src


def test_init_refuses_to_overwrite_a_foreign_plugin_file(tmp_path):
    repo, home = tmp_path / "repo", tmp_path / "home"
    (repo / ".opencode" / "plugins").mkdir(parents=True)
    foreign = repo / ".opencode" / "plugins" / "agent-ledger.js"
    foreign.write_text("// someone else's plugin\n")
    r = cli("init", "--agent", "opencode", "--project", str(repo), home=home)
    assert r.returncode == 1 and foreign.read_text() == "// someone else's plugin\n"


def test_init_does_not_follow_plugin_symlink(tmp_path):
    repo, home, victim = tmp_path / "repo", tmp_path / "home", tmp_path / "victim.txt"
    (repo / ".opencode" / "plugins").mkdir(parents=True)
    victim.write_text("precious")
    (repo / ".opencode" / "plugins" / "agent-ledger.js").symlink_to(victim)
    cli("init", "--agent", "opencode", "--project", str(repo), home=home)
    assert victim.read_text() == "precious"


def test_init_fail_closed_bakes_into_plugin(tmp_path):
    repo, home = tmp_path / "repo", tmp_path / "home"
    repo.mkdir()
    cli("init", "--agent", "opencode", "--fail-closed", "--project", str(repo), home=home)
    assert "const FAIL_CLOSED = true" in (repo / ".opencode" / "plugins" / "agent-ledger.js").read_text()


# ---------------------------------------------------------------- the JS plugin itself, under node

NODE = shutil.which("node")

DRIVER = r"""
const { pathToFileURL } = await import("node:url");
const mod = await import(pathToFileURL(process.argv[2]).href);  // bare C:\ paths are not importable on Windows
// One default export serving both OpenCode versions: V1 calls server(), V2 calls setup().
const names = Object.keys(mod);
const plugin = mod.default;
if (names.join() !== "default" || typeof plugin?.id !== "string" || typeof plugin.server !== "function"
    || typeof plugin.setup !== "function" || "tui" in plugin)
  throw new Error("plugin must have exactly one default export {id, server, setup}, got " + names);
const hooks = await plugin.server({ directory: process.argv[3], worktree: process.argv[3] });
const results = {};
async function before(tool, args, id) {
  try { await hooks["tool.execute.before"]({ tool, sessionID: "ses_n", callID: id }, { args }); return "ran"; }
  catch (e) { return "blocked: " + e.message; }
}
await hooks.event({ event: { type: "session.created", properties: { info: { id: "ses_n" } } } });
await hooks["chat.message"]({ sessionID: "ses_n" }, { message: {}, parts: [{ type: "text", text: "please read the env" }] });
results.deny = await before("bash", { command: "cat .env" }, "c1");
results.ask = await before("bash", { command: "git push origin main" }, "c2");
results.allow = await before("read", { filePath: process.argv[3] + "/a.py" }, "c3");
await hooks["tool.execute.after"]({ tool: "read", sessionID: "ses_n", callID: "c3", args: { filePath: process.argv[3] + "/a.py" } },
                                  { title: "a.py", output: "print(1)", metadata: {} });
await hooks.event({ event: { type: "message.part.updated", properties: { part: { type: "tool", tool: "bash", callID: "c1",
  state: { status: "error", input: { command: "cat .env" }, error: "blocked" } } } } });
await hooks.event({ event: { type: "session.idle", properties: { sessionID: "ses_n" } } });
console.log(JSON.stringify(results));
"""


def render_plugin(tmp_path, hook_argv, fail_closed=False):
    from agent_ledger.init import render_opencode_plugin

    p = tmp_path / "plugin.mjs"
    p.write_text(render_opencode_plugin(hook_argv, fail_closed))
    return p


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_js_plugin_end_to_end_with_real_hook(tmp_path):
    from agent_ledger import queries, store

    repo, home = tmp_path / "repo", tmp_path / "home"
    repo.mkdir()
    plugin = render_plugin(tmp_path, [sys.executable, "-m", "agent_ledger", "hook", "--agent", "opencode"])
    driver = tmp_path / "driver.mjs"
    driver.write_text(DRIVER)
    r = subprocess.run([NODE, str(driver), str(plugin), str(repo)], capture_output=True, text=True, timeout=60,
                       env={**os.environ, "AGENT_LEDGER_HOME": str(home)})
    assert r.returncode == 0, r.stderr
    res = json.loads(r.stdout.strip().splitlines()[-1])
    assert res["deny"].startswith("blocked:") and "secrets.files" in res["deny"]
    assert res["ask"].startswith("blocked:") and "approval" in res["ask"]
    assert res["allow"] == "ran"
    rows = queries.events(store.connect(home / "ledger.db", readonly=True))
    kinds = [r["event_type"] for r in rows]
    assert kinds[:2] == ["SessionStart", "UserPromptSubmit"] and "PostToolUseFailure" in kinds and kinds[-1] == "Stop"
    assert sum(1 for k in kinds if k == "PreToolUse") == 3


@pytest.mark.skipif(NODE is None, reason="node not installed")
@pytest.mark.parametrize("fail_closed,expected", [(False, "ran"), (True, "blocked")])
def test_js_plugin_when_agent_ledger_is_missing(tmp_path, fail_closed, expected):
    plugin = render_plugin(tmp_path, ["/nonexistent/agent-ledger", "hook", "--agent", "opencode"], fail_closed)
    driver = tmp_path / "driver.mjs"
    driver.write_text(DRIVER)
    r = subprocess.run([NODE, str(driver), str(plugin), str(tmp_path)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    res = json.loads(r.stdout.strip().splitlines()[-1])
    assert res["allow"].startswith(expected)


def test_init_next_steps_name_the_right_agent(tmp_path):
    repo, home = tmp_path / "repo", tmp_path / "home"
    repo.mkdir()
    out = cli("init", "--agent", "opencode", "--project", str(repo), home=home).stdout
    assert "OpenCode session" in out and "Claude Code" not in out


# ---------------------------------------------------------------- security review: apply_patch header parsing

@pytest.mark.parametrize("header", [
    "*** Add File:.opencode/plugins/agent-ledger.js",      # no space after colon (OpenCode trims)
    "*** Add File:\t.opencode/plugins/agent-ledger.js",    # tab
    "*** Add File:   .opencode/plugins/agent-ledger.js  ",  # extra spaces
    "*** Update File:.agent-ledger.toml",
    "*** Delete File:.agent-ledger.toml",
    "*** Add File:.env",
])
def test_patch_headers_parsed_like_opencode(env, header):  # noqa: F811
    patch = f"*** Begin Patch\n{header}\n+x\n*** End Patch"
    assert decide(env, "apply_patch", {"patchText": patch}).decision == "deny", header


def test_move_to_without_space_is_checked(env):  # noqa: F811
    patch = "*** Begin Patch\n*** Update File: src/a.py\n*** Move to:.opencode/plugins/agent-ledger.js\n@@\n-a\n+b\n*** End Patch"
    assert decide(env, "apply_patch", {"patchText": patch}).decision == "deny"


def test_heredoc_wrapped_patch_is_parsed(env):  # noqa: F811
    patch = "cat <<'EOF'\n*** Begin Patch\n*** Add File:.env\n+X=1\n*** End Patch\nEOF"
    assert decide(env, "apply_patch", {"patchText": patch}).decision == "deny"


@pytest.mark.parametrize("patch", [
    "*** Begin Patch\n*** Add Fil: x\n+y\n*** End Patch",           # unknown header: no paths found
    "*** Begin Patch\n*** Frobnicate File: x\n*** End Patch",
    "something that is not a patch at all",
    "*** Begin Patch\n*** Add File:\n+y\n*** End Patch",              # empty path
])
def test_patch_with_no_recognised_paths_is_never_allowed(env, patch):  # noqa: F811
    assert decide(env, "apply_patch", {"patchText": patch}).decision != "allow", patch


def test_patch_header_lines_inside_content_still_parse_targets(env):  # noqa: F811
    ok = "*** Begin Patch\n*** Add File: src/ok.py\n+print(1)\n*** End Patch"
    assert decide(env, "apply_patch", {"patchText": ok}).decision == "allow"


# ---------------------------------------------------------------- OpenCode V2 (2.x): tool names and arguments

@pytest.mark.parametrize(
    "tool,args,canon_tool,canon_input",
    [
        ("shell", {"command": "ls", "timeout": 5}, "Bash", {"command": "ls", "timeout": 5}),
        ("edit", {"path": "/r/a.py", "oldString": "a", "newString": "b"}, "Edit",
         {"file_path": "/r/a.py", "old_string": "a", "new_string": "b"}),
        ("write", {"path": "/r/a.py", "content": "x"}, "Write", {"file_path": "/r/a.py", "content": "x"}),
        ("read", {"path": "/r/a.py", "offset": 1}, "Read", {"file_path": "/r/a.py", "offset": 1}),
        ("glob", {"pattern": "*.py", "path": "/r", "hidden": True}, "Glob", {"pattern": "*.py", "path": "/r"}),
        ("grep", {"pattern": "x", "path": "/r", "include": "*.py"}, "Grep", {"pattern": "x", "path": "/r", "glob": "*.py"}),
        ("subagent", {"agent": "general", "description": "d", "prompt": "p"}, "Task",
         {"agent": "general", "description": "d", "prompt": "p"}),
        ("skill", {"id": "s"}, "Skill", {"id": "s"}),
    ],
)
def test_v2_tool_mapping(tool, args, canon_tool, canon_input):
    c = oc.normalize(envelope(tool, args))
    assert c["tool_name"] == canon_tool and c["tool_input"] == canon_input


def test_v2_patch_tool_is_checked_like_apply_patch(env):  # noqa: F811
    patch = "*** Begin Patch\n*** Add File:.opencode/plugins/agent-ledger.js\n+x\n*** End Patch"
    assert oc.normalize(envelope("patch", {"patchText": patch}))["tool_name"] == "ApplyPatch"
    assert decide(env, "patch", {"patchText": patch}).decision == "deny"


@pytest.mark.parametrize("cmd", RM_ROOT + SECRETS + REMOTE_CODE + FORCE_PUSH)
def test_bypass_suites_hold_through_opencode_v2_shell(env, cmd):  # noqa: F811
    assert decide(env, "shell", {"command": env.fmt(cmd)}).decision == "deny", cmd


@pytest.mark.parametrize("tool,args,expected", [
    ("read", {"path": "{proj}/.env"}, "deny"),
    ("write", {"path": "{home}/.zshrc", "content": "x"}, "deny"),
    ("edit", {"path": "{proj}/src/a.py", "oldString": "a", "newString": "b"}, "allow"),
    ("write", {"path": "{proj}/.opencode/plugins/agent-ledger.js", "content": ""}, "deny"),
])
def test_v2_file_tools_use_path_argument(env, tool, args, expected):  # noqa: F811
    args = {k: env.fmt(v) for k, v in args.items()}
    assert decide(env, tool, args).decision == expected


# ---------------------------------------------------------------- the same plugin file under a fake V2 runtime

DRIVER_V2 = r"""
const { pathToFileURL } = await import("node:url");
const plugin = (await import(pathToFileURL(process.argv[2]).href)).default;
const approve = process.argv[4] === "approve";
const hooks = { before: [], after: [], prompt: [] };
const asked = [];
let pushEvent;
const events = { [Symbol.asyncIterator]() { return this; },
  next() { return new Promise((r) => { pushEvent = (e) => r({ value: e, done: false }); }); } };
const ctx = {
  location: { directory: process.argv[3], project: { id: "p", directory: process.argv[3] } },
  tool: { hook: async (name, cb) => { hooks[name === "execute.before" ? "before" : "after"].push(cb); } },
  session: { hook: async (name, cb) => { if (name === "prompt") hooks.prompt.push(cb); } },
  permission: { assert: async (req) => { asked.push(req); if (!approve) throw new Error("user declined"); } },
  event: { subscribe: () => events },
};
await plugin.setup(ctx);
const results = {};
const ev = (type, extra = {}) => { pushEvent && pushEvent({ type, sessionID: "ses_v2", ...extra }); return new Promise((r) => setTimeout(r, 300)); };
async function before(tool, input, id) {
  const e = { tool, sessionID: "ses_v2", agent: "build", messageID: "m1", id, input };
  try { for (const cb of hooks.before) await cb(e); return "ran"; } catch (err) { return "blocked: " + err.message; }
}
await ev("session.created");
for (const cb of hooks.prompt) await cb({ sessionID: "ses_v2", messageID: "m0", prompt: { text: "please tidy up" } });
results.deny = await before("shell", { command: "cat .env" }, "c1");
results.ask = await before("shell", { command: "git push origin main" }, "c2");
results.asked = asked.length;
results.allow = await before("read", { path: process.argv[3] + "/a.py" }, "c3");
for (const cb of hooks.after) await cb({ tool: "read", sessionID: "ses_v2", agent: "build", messageID: "m1", id: "c3",
  input: { path: process.argv[3] + "/a.py" }, status: "completed", result: { output: "print(1)", content: [] } });
for (const cb of hooks.after) await cb({ tool: "shell", sessionID: "ses_v2", agent: "build", messageID: "m1", id: "c4",
  input: { command: "false" }, status: "error", error: { message: "exit 1" } });
results.afterThrows = await (async () => { try { for (const cb of hooks.after) await cb(null); return false; } catch { return true; } })();
await ev("session.execution.succeeded");
await ev("session.deleted");
console.log(JSON.stringify(results));
process.exit(0);
"""


def run_v2(tmp_path, hook_argv, approve, fail_closed=False, home=None):
    plugin = render_plugin(tmp_path, hook_argv, fail_closed)
    driver = tmp_path / "driver_v2.mjs"
    driver.write_text(DRIVER_V2)
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    r = subprocess.run([NODE, str(driver), str(plugin), str(repo), "approve" if approve else "decline"],
                       capture_output=True, text=True, timeout=90,
                       env={**os.environ, "AGENT_LEDGER_HOME": str(home or tmp_path / "home")})
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout.strip().splitlines()[-1])


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_v2_plugin_deny_ask_allow_and_recording(tmp_path):
    from agent_ledger import queries, store

    hook = [sys.executable, "-m", "agent_ledger", "hook", "--agent", "opencode"]
    res = run_v2(tmp_path, hook, approve=False)
    assert res["deny"].startswith("blocked:") and "secrets.files" in res["deny"]
    assert res["ask"].startswith("blocked:") and res["asked"] == 1     # V2 really asked the user, who declined
    assert res["allow"] == "ran" and res["afterThrows"] is False        # after-hook must never throw
    rows = queries.events(store.connect(tmp_path / "home" / "ledger.db", readonly=True))
    kinds = [r["event_type"] for r in rows]
    assert kinds[0] == "SessionStart" and "UserPromptSubmit" in kinds
    assert kinds.count("PreToolUse") == 3 and "PostToolUse" in kinds and "PostToolUseFailure" in kinds
    assert "Stop" in kinds and kinds[-1] == "SessionEnd"
    assert {r["agent"] for r in rows} == {"opencode"}


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_v2_ask_approved_by_user_runs(tmp_path):
    res = run_v2(tmp_path, [sys.executable, "-m", "agent_ledger", "hook", "--agent", "opencode"], approve=True)
    assert res["ask"] == "ran" and res["asked"] == 1 and res["deny"].startswith("blocked:")


@pytest.mark.skipif(NODE is None, reason="node not installed")
@pytest.mark.parametrize("fail_closed,expected", [(False, "ran"), (True, "blocked")])
def test_v2_plugin_when_agent_ledger_is_missing(tmp_path, fail_closed, expected):
    res = run_v2(tmp_path, ["/nonexistent/agent-ledger", "hook", "--agent", "opencode"], approve=True,
                 fail_closed=fail_closed)
    assert res["allow"].startswith(expected)


def test_init_upgrades_an_older_agent_ledger_plugin(tmp_path):
    repo, home = tmp_path / "repo", tmp_path / "home"
    (repo / ".opencode" / "plugins").mkdir(parents=True)
    old = repo / ".opencode" / "plugins" / "agent-ledger.js"
    old.write_text("// agent-ledger plugin for OpenCode (V1 plugin API, opencode 1.x). agent-ledger-plugin:v1\nexport const AgentLedger = async () => ({})\n")
    r = cli("init", "--agent", "opencode", "--project", str(repo), home=home)
    assert r.returncode == 0, r.stderr
    src = old.read_text()
    assert "agent-ledger-plugin:v2" in src and "async setup(ctx)" in src and "async server(" in src
