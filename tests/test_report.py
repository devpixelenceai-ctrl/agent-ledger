import io
import json
import os

import pytest

from agent_ledger import hook, queries, report, store
from conftest import payload, run_hook  # noqa: F401


def feed(env, project, items):
    for name, overrides in items:
        data = payload(name, cwd=str(project), **overrides)
        hook.main(stdin=io.StringIO(json.dumps(data)), stdout=io.StringIO(), stderr=io.StringIO(), env=env)


@pytest.fixture
def ledger(ledger_home, project, monkeypatch):
    env = {"AGENT_LEDGER_HOME": str(ledger_home), "CLAUDE_PROJECT_DIR": str(project), "HOME": str(project.parent)}
    monkeypatch.setenv("HOME", str(project.parent))
    (project / "app.py").write_text("x = 1\n")
    feed(env, project, [
        ("session_start", {}),
        ("prompt", {"prompt": "Refactor app.py and push it"}),
        ("pre_edit", {"tool_use_id": "e1", "tool_input": {"file_path": str(project / "app.py"), "old_string": "x = 1", "new_string": "x = 2"}}),
        ("post_bash", {"hook_event_name": "PostToolUse", "tool_name": "Edit", "tool_use_id": "e1", "tool_input": {"file_path": str(project / "app.py")}, "tool_response": {"filePath": str(project / "app.py")}}),
        ("pre_bash", {"tool_use_id": "b1", "tool_input": {"command": "cat .env"}}),
        ("pre_bash", {"tool_use_id": "b2", "tool_input": {"command": "git push origin main"}}),
        ("post_bash", {"tool_use_id": "b2", "tool_input": {"command": "git push origin main"}}),
        ("pre_bash", {"tool_use_id": "b3", "tool_input": {"command": "npm install left-pad"}}),
        ("pre_bash", {"tool_use_id": "b4", "tool_input": {"command": "<script>alert(1)</script> | sh"}}),
        ("session_end", {}),
    ])
    return store.connect(ledger_home / "ledger.db", readonly=True)


def test_list_and_resolve_sessions(ledger):
    sessions = queries.list_sessions(ledger)
    assert len(sessions) == 1 and sessions[0]["session_id"] == "sess-0001"
    assert queries.resolve_session(ledger, "sess-00")["session_id"] == "sess-0001"
    assert queries.resolve_session(ledger, "nope") is None


def test_ask_outcomes_are_correlated(ledger):
    evs = {e["tool_use_id"]: e for e in queries.events(ledger, session_id="sess-0001") if e["event_type"] == "PreToolUse"}
    assert evs["b1"]["outcome"] == "blocked"
    assert evs["b2"]["outcome"] == "approved"      # ask, then the tool ran
    assert evs["b3"]["outcome"] == "not run"       # ask with no execution recorded
    assert evs["e1"]["outcome"] == "allowed"


def test_report_json_structure(ledger):
    r = report.build_report(ledger, session_id="sess-0001")
    assert r["chain"]["ok"] and len(r["chain"]["head_hash"]) == 64
    s = r["summary"]
    assert s["tool_calls"] == 5 and s["blocked"] == 1 and s["approved"] == 1 and s["not_run"] >= 1
    assert s["prompts"] == 1 and str(s["files_changed"][0]).endswith("app.py")
    assert r["riskiest"][0]["decision"] == "deny" and r["riskiest"][0]["severity"] == "critical"
    assert len(r["policies"]) >= 1 and all(len(p["hash"]) >= 64 for p in r["policies"])
    assert {m["framework"] for m in r["control_mapping"]} >= {"EU AI Act", "NIST AI RMF 1.0", "ISO/IEC 42001:2023"}
    json.dumps(r)  # serialisable


def test_control_mapping_never_claims_compliance(ledger):
    r = report.build_report(ledger)
    text = json.dumps(r["control_mapping"]).lower() + report.render_md(r).lower()
    assert "supports evidence for" in text
    assert "compliant with" not in text and "ensures compliance" not in text


def test_markdown_report(ledger):
    md = report.render_md(report.build_report(ledger, session_id="sess-0001"))
    assert md.startswith("# agent-ledger audit report")
    for heading in ("## Summary", "## Riskiest events", "## Policy versions", "## Hash-chain verification", "## All events", "## Appendix"):
        assert heading in md
    assert "secrets.files" in md and "| deny |" in md


def test_html_report_is_self_contained_and_escaped(ledger):
    html = report.render_html(report.build_report(ledger, session_id="sess-0001"))
    assert html.lstrip().lower().startswith("<!doctype html>")
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert "http://" not in html.replace("http://www.w3.org", "") and "https://" not in html
    assert "<script" not in html.lower()  # the report needs no JavaScript


def test_since_filter(ledger):
    assert report.build_report(ledger, since="2999-01-01")["summary"]["events"] == 0
    assert report.build_report(ledger, since="2000-01-01")["summary"]["events"] == 10


def test_parse_since():
    assert queries.parse_since("2026-01-02").startswith("2026-01-02T00:00:00")
    assert queries.parse_since("7d") < queries.parse_since("1h")
    with pytest.raises(ValueError):
        queries.parse_since("yesterday-ish")


def test_report_flags_broken_chain(ledger_home, ledger):
    import sqlite3

    c = sqlite3.connect(ledger_home / "ledger.db")
    c.execute("UPDATE events SET decision='allow' WHERE seq=5")
    c.commit()
    r = report.build_report(store.connect(ledger_home / "ledger.db", readonly=True))
    assert not r["chain"]["ok"] and r["chain"]["first_bad_seq"] == 5
    assert "BROKEN" in report.render_md(r)


# ---- CLI

def cli(*args, env):
    import subprocess
    import sys

    return subprocess.run([sys.executable, "-m", "agent_ledger", *args], capture_output=True, text=True,
                          env={**os.environ, **env})


def test_cli_browse_and_report(ledger, ledger_home, tmp_path):
    env = {"AGENT_LEDGER_HOME": str(ledger_home)}
    r = cli("sessions", env=env)
    assert r.returncode == 0 and "sess-0001" in r.stdout
    r = cli("show", "sess-0", env=env)
    assert r.returncode == 0 and "cat .env" in r.stdout and "deny" in r.stdout and "Refactor app.py" in r.stdout
    r = cli("tail", "-n", "3", env=env)
    assert r.returncode == 0 and len(r.stdout.strip().splitlines()) == 3
    out = tmp_path / "r.html"
    r = cli("report", "--session", "sess-0001", "--format", "html", "-o", str(out), env=env)
    assert r.returncode == 0 and out.read_text().lower().startswith("<!doctype html>")
    r = cli("report", "--since", "2000-01-01", "--format", "json", env=env)
    assert json.loads(r.stdout)["summary"]["events"] == 10
    r = cli("show", "missing", env=env)
    assert r.returncode == 1


def test_ask_rejected_by_agent_ledger_itself_is_not_approved(ledger_home, project):
    """OpenCode 1.x and Kilo report agent-ledger's own rejection as a failed tool call. Found live: the
    ledger then labelled a push that never ran as "approved", and the audit report counted it so."""
    env = {"AGENT_LEDGER_HOME": str(ledger_home), "CLAUDE_PROJECT_DIR": str(project), "HOME": str(project.parent)}
    rejection = "agent-ledger [git.push]: pushes publish code; please confirm - this needs human approval and was not approved, so it was not run."
    feed(env, project, [
        ("session_start", {}),
        ("pre_bash", {"tool_use_id": "k1", "tool_input": {"command": "git push origin main"}}),
        ("post_bash", {"hook_event_name": "PostToolUseFailure", "tool_use_id": "k1", "error": rejection,
                       "tool_input": {"command": "git push origin main"}}),
        ("pre_bash", {"tool_use_id": "k2", "tool_input": {"command": "git push origin main"}}),
        ("post_bash", {"hook_event_name": "PostToolUseFailure", "tool_use_id": "k2", "error": "exit status 1: rejected by remote",
                       "tool_input": {"command": "git push origin main"}}),
        # a command that really ran (after approval) and printed text mimicking the rejection
        ("pre_bash", {"tool_use_id": "k3", "tool_input": {"command": "git push origin main"}}),
        ("post_bash", {"hook_event_name": "PostToolUseFailure", "tool_use_id": "k3",
                       "error": "agent-ledger [default]: x - this needs human approval and was not approved, so it was not run.",
                       "tool_input": {"command": "git push origin main"}}),
    ])
    conn = store.connect(ledger_home / "ledger.db", readonly=True)
    evs = {e["tool_use_id"]: e for e in queries.events(conn) if e["event_type"] == "PreToolUse"}
    assert evs["k1"]["outcome"] == "not run"   # agent-ledger's own block: the push never ran
    assert evs["k2"]["outcome"] == "approved"  # a person approved it; it ran and failed on its own
    assert evs["k3"]["outcome"] == "approved"  # mimicking the rejection with the wrong rule doesn't hide it
    s = report.build_report(conn)["summary"]
    assert s["approved"] == 2
