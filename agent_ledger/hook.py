"""`agent-ledger hook`: the hot path. Must never crash the agent's session.

Error handling contract (docs/hook-contract.md section 5):
- A policy decision is printed only on the success path (JSON on stdout, exit 0).
- Internal error with fail_mode="open" (default): log it, print nothing, exit 0.
  Claude Code then applies its normal permission flow.
- Internal error with fail_mode="closed": PreToolUse exits 2 (the call is blocked and
  stderr goes to Claude). Every other event still exits 0, so the session keeps working.
- If the event cannot be recorded, a policy decision still stands; in closed mode an
  unrecordable PreToolUse is blocked, because an unaudited action is what closed mode forbids.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

from agent_ledger import store
from agent_ledger.adapters import claude_code as adapter
from agent_ledger.config import Config, ledger_home, load_config
from agent_ledger.model import Decision, Event
from agent_ledger.redact import redact_str

ERROR_LOG_MAX = 1_000_000
BLOCK_MSG = "agent-ledger: internal error and fail_mode=closed, so this tool call is blocked. See {log}"


def evaluate(ev: Event, cfg: Config) -> Decision | None:
    """Policy hook point. Replaced by the policy engine in M2."""
    return None


def _tb() -> str:
    import traceback

    return traceback.format_exc()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def log_error(env, msg: str) -> None:
    try:
        home = ledger_home(env)
        home.mkdir(parents=True, exist_ok=True, mode=0o700)
        log = home / "errors.log"
        if log.exists() and log.stat().st_size > ERROR_LOG_MAX:
            os.replace(log, home / "errors.log.1")
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(f"{_now()} {redact_str(msg)}\n")
    except Exception:
        pass  # logging must never be the thing that breaks the session


def _fail(cfg: Config | None, env, event_type: str | None, stderr) -> int:
    if cfg is not None and cfg.fail_closed and event_type in (None, "PreToolUse"):
        stderr.write(BLOCK_MSG.format(log=ledger_home(env) / "errors.log") + "\n")
        return 2
    return 0


def _record(cfg: Config, ev: Event, decision: Decision | None, error: BaseException | None) -> None:
    payload = adapter.stored_payload(ev.raw, cfg.max_field_chars)
    row = {
        "ts": _now(),
        "agent": ev.agent,
        "session_id": ev.session_id,
        "event_type": ev.event_type,
        "tool_name": ev.tool_name,
        "tool_use_id": ev.tool_use_id,
        "summary": adapter.summarize(ev.raw),
        "payload": json.dumps(payload, sort_keys=True, ensure_ascii=False),
        "decision": decision.decision if decision else None,
        "rule_id": decision.rule_id if decision else None,
        "severity": decision.severity if decision else None,
        "reason": decision.reason if decision else None,
        "policy_hash": (decision.policy_hash if decision else None) or "none",
    }
    if error is not None:
        row.update(decision="error", reason=redact_str(f"{type(error).__name__}: {error}")[:500])
    conn = store.connect(cfg.db_path)
    try:
        store.append(conn, row, key=cfg.hmac_key, session_meta=adapter.session_meta(ev.raw))
    finally:
        conn.close()


def main(stdin=None, stdout=None, stderr=None, env=None) -> int:
    stdin, stdout, stderr = stdin or sys.stdin, stdout or sys.stdout, stderr or sys.stderr
    env = os.environ if env is None else env
    cfg: Config | None = None
    event_type: str | None = None
    try:
        cfg = load_config(env)
        for w in cfg.warnings:
            log_error(env, f"config warning: {w}")
        if stdin.isatty():
            stderr.write("agent-ledger hook expects hook JSON on stdin (it is run by Claude Code).\n")
            return 0
        data = json.loads(stdin.read())
        if not isinstance(data, dict):
            raise ValueError("hook input is not a JSON object")
        event_type = data.get("hook_event_name")
        ev = adapter.to_event(data, env)
    except BaseException:
        log_error(env, "hook input error:\n" + _tb())
        return _fail(cfg, env, event_type, stderr)

    decision, error = None, None
    try:
        decision = evaluate(ev, cfg)
    except BaseException as e:
        error = e
        log_error(env, "policy error:\n" + _tb())

    recorded = True
    try:
        _record(cfg, ev, decision, error)
    except BaseException:
        recorded = False
        log_error(env, "record error:\n" + _tb())

    if error is not None:
        return _fail(cfg, env, event_type, stderr)
    if not recorded and cfg.fail_closed and event_type == "PreToolUse":
        stderr.write(BLOCK_MSG.format(log=ledger_home(env) / "errors.log") + "\n")
        return 2
    out, code = adapter.render(decision, ev.event_type)
    if out:
        stdout.write(out)
    return code
