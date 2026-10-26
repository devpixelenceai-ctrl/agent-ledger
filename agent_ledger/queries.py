"""Read-side queries shared by the CLI, the report and the dashboard. Never writes."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, None: 0}
DECISION_RANK = {"deny": 3, "error": 3, "ask": 2, "allow": 1, None: 0}
TOOL_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionRequest", "PermissionDenied")
FILE_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit", "ApplyPatch")


def parse_since(value: str) -> str:
    """'2026-01-31', an ISO timestamp, or a relative '7d' / '12h' / '30m' -> ISO-8601 UTC string."""
    v = value.strip()
    m = re.fullmatch(r"(\d+)([dhm])", v)
    if m:
        n, unit = int(m.group(1)), m.group(2)
        delta = {"d": timedelta(days=n), "h": timedelta(hours=n), "m": timedelta(minutes=n)}[unit]
        dt = datetime.now(timezone.utc) - delta
    else:
        try:
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError as e:
            raise ValueError(f"cannot parse date {value!r}: use YYYY-MM-DD, an ISO timestamp, or 7d / 12h / 30m") from e
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def list_sessions(conn, since: str | None = None, limit: int | None = None) -> list[dict]:
    sql = "SELECT * FROM sessions"
    params: list = []
    if since:
        sql += " WHERE COALESCE(last_event_at, started_at) >= ?"
        params.append(since)
    sql += " ORDER BY started_at DESC"
    if limit:
        sql += " LIMIT ?"
        params.append(int(limit))
    return [dict(r) for r in conn.execute(sql, params)]


def resolve_session(conn, prefix: str) -> dict | None:
    """Exact id, or a unique prefix."""
    r = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (prefix,)).fetchone()
    if r:
        return dict(r)
    escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    rows = conn.execute("SELECT * FROM sessions WHERE session_id LIKE ? ESCAPE '\\' LIMIT 2", (escaped + "%",)).fetchall()
    return dict(rows[0]) if len(rows) == 1 else None


def _outcomes(rows: list[dict]) -> None:
    """Annotate PreToolUse rows with what happened: allowed / approved / denied / blocked / not run."""
    ran = {r["tool_use_id"] for r in rows if r["event_type"] in ("PostToolUse", "PostToolUseFailure") and r["tool_use_id"]}
    denied_ids = {r["tool_use_id"] for r in rows if r["event_type"] == "PermissionDenied" and r["tool_use_id"]}
    for r in rows:
        if r["event_type"] != "PreToolUse":
            r["outcome"] = None
            continue
        d = r["decision"]
        if d == "deny":
            r["outcome"] = "blocked"
        elif d == "ask":
            if r["tool_use_id"] in ran:
                r["outcome"] = "approved"
            elif r["tool_use_id"] in denied_ids:
                r["outcome"] = "denied"
            else:
                r["outcome"] = "not run"
        elif d == "allow":
            r["outcome"] = "allowed"
        elif d == "error":
            r["outcome"] = "error"
        else:
            r["outcome"] = "ran" if r["tool_use_id"] in ran else "recorded"


def events(conn, session_id: str | None = None, since: str | None = None, after_seq: int | None = None,
           limit: int | None = None, newest_first: bool = False) -> list[dict]:
    sql = "SELECT * FROM events WHERE 1=1"
    params: list = []
    if session_id:
        sql += " AND session_id = ?"
        params.append(session_id)
    if since:
        sql += " AND ts >= ?"
        params.append(since)
    if after_seq is not None:
        sql += " AND seq > ?"
        params.append(after_seq)
    sql += " ORDER BY seq DESC" if newest_first else " ORDER BY seq"
    if limit:
        sql += " LIMIT ?"
        params.append(int(limit))
    rows = [dict(r) for r in conn.execute(sql, params)]
    if newest_first:
        rows.reverse()
    _outcomes(rows)
    return rows


def payload(row: dict) -> dict:
    try:
        p = json.loads(row.get("payload") or "{}")
        return p if isinstance(p, dict) else {}
    except ValueError:
        return {}


def risk_key(r: dict):
    return (SEVERITY_RANK.get(r.get("severity"), 0), DECISION_RANK.get(r.get("decision"), 0), r["seq"])
