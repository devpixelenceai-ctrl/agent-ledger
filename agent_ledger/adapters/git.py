"""Git-hook fallback (agent_ledger/githook.py): payloads are already canonical, recorded as agent "git"."""

from __future__ import annotations

from agent_ledger.adapters import claude_code as _cc
from agent_ledger.model import Event

AGENT = "git"


def to_event(data: dict, env) -> Event:
    ev = _cc.to_event(data, {})
    ev.agent = AGENT
    return ev


stored_payload = _cc.stored_payload
summarize = _cc.summarize
session_meta = _cc.session_meta
render = _cc.render
