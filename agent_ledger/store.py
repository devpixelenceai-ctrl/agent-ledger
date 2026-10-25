"""SQLite storage: an append-only, hash-chained `events` table plus a derived `sessions` summary."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from agent_ledger.chain import GENESIS, VerifyResult, compute_hash, verify_rows

SCHEMA_VERSION = 1

CHAINED_FIELDS = (
    "seq", "ts", "agent", "session_id", "event_type", "tool_name", "tool_use_id", "summary",
    "payload", "decision", "rule_id", "severity", "reason", "policy_hash",
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    agent TEXT NOT NULL,
    session_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    tool_name TEXT,
    tool_use_id TEXT,
    summary TEXT,
    payload TEXT,
    decision TEXT,
    rule_id TEXT,
    severity TEXT,
    reason TEXT,
    policy_hash TEXT,
    prev_hash TEXT NOT NULL,
    row_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_session ON events(session_id, seq);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    agent TEXT,
    started_at TEXT,
    ended_at TEXT,
    last_event_at TEXT,
    cwd TEXT,
    git_branch TEXT,
    git_commit TEXT,
    model TEXT,
    transcript_path TEXT,
    end_reason TEXT,
    tool_calls INTEGER NOT NULL DEFAULT 0,
    blocked INTEGER NOT NULL DEFAULT 0,
    asked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


def connect(path, readonly: bool = False) -> sqlite3.Connection:
    path = Path(path)
    if readonly:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only = ON")
        return conn
    old = os.umask(0o077)
    try:
        if not path.parent.exists():
            path.parent.mkdir(parents=True, mode=0o700)
        new = not path.exists()
        conn = sqlite3.connect(path, timeout=10, isolation_level=None)
    finally:
        os.umask(old)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 10000")
    conn.execute("PRAGMA synchronous = NORMAL")
    if new or conn.execute("PRAGMA journal_mode").fetchone()[0] != "wal":
        conn.execute("PRAGMA journal_mode = WAL")
    if new or not conn.execute("SELECT 1 FROM sqlite_master WHERE name='events'").fetchone():
        conn.executescript(_SCHEMA)
        conn.execute("INSERT OR IGNORE INTO meta VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
    return conn


def _fields(row) -> dict:
    return {k: row[k] for k in CHAINED_FIELDS}


def append(conn: sqlite3.Connection, row: dict, key: bytes | None = None, session_meta: dict | None = None):
    """Append one event atomically. BEGIN IMMEDIATE serialises concurrent hook processes."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        last = conn.execute("SELECT seq, row_hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        seq, prev = (last[0] + 1, last[1]) if last else (1, GENESIS)
        fields = {k: row.get(k) for k in CHAINED_FIELDS}
        fields["seq"] = seq
        h = compute_hash(prev, fields, key)
        cols = ", ".join(CHAINED_FIELDS)
        conn.execute(
            f"INSERT INTO events ({cols}, prev_hash, row_hash) VALUES ({', '.join('?' * len(CHAINED_FIELDS))}, ?, ?)",
            [fields[k] for k in CHAINED_FIELDS] + [prev, h],
        )
        _update_session(conn, fields, session_meta or {})
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return seq, h


def _update_session(conn, f: dict, meta: dict) -> None:
    sid, ts, et, decision = f["session_id"], f["ts"], f["event_type"], f["decision"]
    conn.execute(
        "INSERT OR IGNORE INTO sessions (session_id, agent, started_at, cwd) VALUES (?, ?, ?, ?)",
        (sid, f["agent"], ts, meta.get("cwd")),
    )
    conn.execute("UPDATE sessions SET last_event_at = ? WHERE session_id = ?", (ts, sid))
    if et == "SessionStart":
        # Resume / clear / compact re-fire SessionStart: keep the original values.
        for col in ("cwd", "git_branch", "git_commit", "model", "transcript_path"):
            if meta.get(col) is not None:
                conn.execute(f"UPDATE sessions SET {col} = COALESCE({col}, ?) WHERE session_id = ?", (meta[col], sid))
    elif et == "PreToolUse":
        conn.execute(
            "UPDATE sessions SET tool_calls = tool_calls + 1, blocked = blocked + ?, asked = asked + ? "
            "WHERE session_id = ?",
            (int(decision == "deny"), int(decision == "ask"), sid),
        )
    elif et == "SessionEnd":
        conn.execute(
            "UPDATE sessions SET ended_at = ?, end_reason = ? WHERE session_id = ?", (ts, meta.get("end_reason"), sid)
        )


def get_session(conn, session_id: str) -> dict | None:
    r = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
    return dict(r) if r else None


def verify(conn, key: bytes | None = None) -> VerifyResult:
    rows = conn.execute(f"SELECT {', '.join(CHAINED_FIELDS)}, prev_hash, row_hash FROM events ORDER BY seq")
    return verify_rows(rows, _fields, key)
