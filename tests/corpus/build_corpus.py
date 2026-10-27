"""Build tests/corpus/real_sessions.jsonl from real recorded ledgers (run once, by hand).

Every PreToolUse decision from a real agent session becomes a frozen regression case. Machine paths
are rewritten to {project} / {home} placeholders, and payloads are already redacted by the ledger.

    .venv/bin/python tests/corpus/build_corpus.py trial/ledgers/django ... > tests/corpus/real_sessions.jsonl
"""

import json
import os
import sqlite3
import sys
from pathlib import Path


def rewrite(obj, project: str, home: str):
    if isinstance(obj, str):
        return obj.replace(project, "{project}").replace(home, "{home}")
    if isinstance(obj, dict):
        return {k: rewrite(v, project, home) for k, v in obj.items()}
    if isinstance(obj, list):
        return [rewrite(v, project, home) for v in obj]
    return obj


def main(ledgers: list[str]) -> None:
    home = os.path.expanduser("~")
    for led in ledgers:
        db = sqlite3.connect(f"file:{Path(led) / 'ledger.db'}?mode=ro", uri=True)
        db.row_factory = sqlite3.Row
        sessions = {r["session_id"]: r["cwd"] for r in db.execute("SELECT session_id, cwd FROM sessions")}
        for r in db.execute("SELECT * FROM events WHERE event_type = 'PreToolUse' ORDER BY seq"):
            payload = json.loads(r["payload"] or "{}")
            project = sessions.get(r["session_id"]) or payload.get("cwd") or ""
            ti = rewrite(payload.get("tool_input") or {}, project, home)
            print(json.dumps({
                "source": f"{Path(led).name}#{r['seq']}",
                "agent": r["agent"],
                "tool": r["tool_name"],
                "tool_input": ti,
                "recorded": {"decision": r["decision"], "rule": r["rule_id"]},
            }, sort_keys=True, ensure_ascii=False))


if __name__ == "__main__":
    main(sys.argv[1:])
