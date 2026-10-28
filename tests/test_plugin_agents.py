"""Agents governed through an in-process plugin instead of a command hook: Kilo Code (OpenCode's V1
plugin API) and Amp (its own plugin API). Each plugin calls `agent-ledger hook --agent <name>`."""

import json
import os
import shutil
import subprocess
import sys

import pytest

from agent_ledger import queries, store
from agent_ledger.init import install_amp_plugin, install_opencode_plugin, render_amp_plugin
from test_opencode import DRIVER, render_plugin

NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node not installed")


def hook(agent):
    return [sys.executable, "-m", "agent_ledger", "hook", "--agent", agent]


# ---------------------------------------------------------------- Kilo Code

def test_kilo_plugin_goes_in_kilos_plugin_dir(tmp_path):
    assert install_opencode_plugin(tmp_path, hook("kilo"), dest=".kilo/plugins") is True
    text = (tmp_path / ".kilo" / "plugins" / "agent-ledger.js").read_text()
    assert '"--agent", "kilo"' in text
    assert not (tmp_path / ".opencode").exists()


@needs_node
def test_kilo_plugin_end_to_end_records_as_kilo(tmp_path):
    repo, home = tmp_path / "repo", tmp_path / "home"
    repo.mkdir()
    plugin = render_plugin(tmp_path, hook("kilo"))
    driver = tmp_path / "driver.mjs"
    driver.write_text(DRIVER)
    r = subprocess.run([NODE, str(driver), str(plugin), str(repo)], capture_output=True, text=True, timeout=60,
                       env={**os.environ, "AGENT_LEDGER_HOME": str(home)})
    assert r.returncode == 0, r.stderr
    res = json.loads(r.stdout.strip().splitlines()[-1])
    assert res["deny"].startswith("blocked:") and res["allow"] == "ran"
    rows = queries.events(store.connect(home / "ledger.db", readonly=True))
    assert {row["agent"] for row in rows} == {"kilo"}


# ---------------------------------------------------------------- Amp

AMP_DRIVER = r"""
const { pathToFileURL } = await import("node:url");
const mod = await import(pathToFileURL(process.argv[2]).href);
const repo = process.argv[3];
const handlers = {};
const amp = {
  on: (name, fn) => { handlers[name] = fn; },
  system: { workspaceRoot: repo },
  helpers: { shellCommandFromToolCall: (e) => e.tool === "Bash" ? { command: e.input.cmd, dir: e.input.cwd } : undefined },
};
await mod.default(amp);
const call = (tool, input, id, confirm) => handlers["tool.call"](
  { toolUseID: id, tool, input, thread: { id: "T-1" } },
  confirm === undefined ? {} : { ui: { confirm: async () => confirm } });
const r = {};
r.deny = await call("Bash", { cmd: "cat .env", cwd: repo }, "t1", true);
r.askNo = await call("Bash", { cmd: "git push origin main", cwd: repo }, "t2", false);
r.askYes = await call("Bash", { cmd: "git push origin main", cwd: repo }, "t3", true);
r.askNoUi = await call("Bash", { cmd: "git push origin main", cwd: repo }, "t4");
r.allow = await call("Read", { path: repo + "/a.py" }, "t5", true);
r.secretRead = await call("Read", { path: repo + "/.env" }, "t6", true);
await handlers["tool.result"]({ toolUseID: "t5", tool: "Read", input: { path: repo + "/a.py" }, status: "done",
                                output: "print(1)", thread: { id: "T-1" } }, {});
console.log(JSON.stringify(r));
"""


def run_amp(tmp_path, argv, fail_closed=False, home=None):
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    plugin = tmp_path / "amp-plugin.mjs"  # the plugin is plain JavaScript in a .ts file; Node imports it as .mjs
    plugin.write_text(render_amp_plugin(argv, fail_closed))
    driver = tmp_path / "amp-driver.mjs"
    driver.write_text(AMP_DRIVER)
    env = {**os.environ, "AGENT_LEDGER_HOME": str(home or tmp_path / "home")}
    r = subprocess.run([NODE, str(driver), str(plugin), str(repo)], capture_output=True, text=True, timeout=60, env=env)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout.strip().splitlines()[-1])


@needs_node
def test_amp_plugin_end_to_end(tmp_path):
    home = tmp_path / "home"
    r = run_amp(tmp_path, hook("amp"), home=home)
    assert r["deny"]["action"] == "reject-and-continue" and "secrets.files" in r["deny"]["message"]
    assert r["askNo"]["action"] == "reject-and-continue" and "approval" in r["askNo"]["message"]
    assert r["askYes"] == {"action": "allow"}  # the person said yes in Amp's own prompt
    assert r["askNoUi"]["action"] == "reject-and-continue"  # no way to ask: never allowed silently
    assert r["allow"] == {"action": "allow"}
    assert r["secretRead"]["action"] == "reject-and-continue"
    rows = queries.events(store.connect(home / "ledger.db", readonly=True))
    assert {row["agent"] for row in rows} == {"amp"}
    assert [row["event_type"] for row in rows].count("PostToolUse") == 1
    assert all(row["tool_name"] in ("Bash", "Read") for row in rows)


@needs_node
@pytest.mark.parametrize("fail_closed,expected", [(False, "allow"), (True, "reject-and-continue")])
def test_amp_plugin_when_agent_ledger_is_missing(tmp_path, fail_closed, expected):
    r = run_amp(tmp_path, ["/nonexistent/agent-ledger", "hook", "--agent", "amp"], fail_closed)
    assert r["allow"]["action"] == expected


def test_amp_install_is_safe_and_idempotent(tmp_path):
    assert install_amp_plugin(tmp_path, hook("amp")) is True
    assert install_amp_plugin(tmp_path, hook("amp")) is False
    other = tmp_path / "o"
    (other / ".amp" / "plugins").mkdir(parents=True)
    (other / ".amp" / "plugins" / "agent-ledger.ts").write_text("export default () => {}\n")
    from agent_ledger.init import InitError

    with pytest.raises(InitError):
        install_amp_plugin(other, hook("amp"))


@pytest.mark.parametrize("agent,path", [("kilo", ".kilo/plugins/agent-ledger.js"), ("amp", ".amp/plugins/agent-ledger.ts")])
def test_init_cli_installs_plugin_agents(tmp_path, agent, path):
    proj, home = tmp_path / "p", tmp_path / "h"
    proj.mkdir()
    r = subprocess.run([sys.executable, "-m", "agent_ledger", "init", "--agent", agent, "--project", str(proj)],
                       capture_output=True, text=True, env={**os.environ, "AGENT_LEDGER_HOME": str(home)}, timeout=60)
    assert r.returncode == 0, r.stderr
    assert (proj / path).exists() and f'"--agent", "{agent}"' in (proj / path).read_text()
