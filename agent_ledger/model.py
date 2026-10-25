"""Agent-agnostic data model. Adapters translate native payloads into these.

Plain classes rather than dataclasses: `dataclasses` pulls in `inspect`, which costs
milliseconds on the hook hot path.
"""

from __future__ import annotations


class Event:
    __slots__ = ("agent", "session_id", "event_type", "tool_name", "tool_use_id", "cwd", "project_dir", "raw")

    def __init__(self, agent, session_id, event_type, tool_name, tool_use_id, cwd, project_dir, raw=None):
        self.agent = agent
        self.session_id = session_id
        self.event_type = event_type  # canonical names follow Claude Code: PreToolUse, SessionStart, ...
        self.tool_name = tool_name
        self.tool_use_id = tool_use_id
        self.cwd = cwd
        self.project_dir = project_dir
        self.raw = raw if raw is not None else {}

    @property
    def tool_input(self) -> dict:
        ti = self.raw.get("tool_input")
        return ti if isinstance(ti, dict) else {}


class Decision:
    __slots__ = ("decision", "rule_id", "severity", "reason", "policy_hash")

    def __init__(self, decision, rule_id=None, severity=None, reason=None, policy_hash=None):
        self.decision = decision  # allow | ask | deny
        self.rule_id = rule_id
        self.severity = severity
        self.reason = reason
        self.policy_hash = policy_hash

    def __repr__(self):
        return f"Decision({self.decision!r}, {self.rule_id!r}, {self.severity!r}, {self.reason!r})"

    def __eq__(self, other):
        return isinstance(other, Decision) and all(getattr(self, s) == getattr(other, s) for s in self.__slots__)
