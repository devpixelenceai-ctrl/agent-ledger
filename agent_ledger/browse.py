"""Terminal views: `sessions`, `show`, `tail`, `report`."""

from __future__ import annotations

import os
import sys
import time

from agent_ledger import queries, store
from agent_ledger.config import load_config

_COLORS = {"deny": "31", "error": "31", "ask": "33", "allow": "32", "blocked": "31", "approved": "32",
           "denied": "31", "not run": "33"}


def _use_color() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(text: str, key: str | None) -> str:
    code = _COLORS.get(key or "")
    return f"\x1b[{code}m{text}\x1b[0m" if code and _use_color() else text


def _open(args):
    cfg = load_config(os.environ)
    db = cfg.db_path if not getattr(args, "db", None) else args.db
    if not os.path.exists(db):
        print(f"No ledger at {db} yet. Run `agent-ledger init` in a project and start a Claude Code session.")
        return None, cfg
    return store.connect(db, readonly=True), cfg


def _short_ts(ts: str | None) -> str:
    return (ts or "")[:19].replace("T", " ")


def cmd_sessions(args) -> int:
    conn, _ = _open(args)
    if conn is None:
        return 0
    since = queries.parse_since(args.since) if args.since else None
    rows = queries.list_sessions(conn, since=since, limit=args.limit)
    if not rows:
        print("No sessions recorded.")
        return 0
    print(f"{'SESSION':<14} {'STARTED (UTC)':<19}  {'CALLS':>5} {'BLOCKED':>7} {'ASKED':>5}  {'BRANCH':<16} DIRECTORY")
    for s in rows:
        blocked = _c(f"{s['blocked']:>7}", "deny" if s["blocked"] else None)
        asked = _c(f"{s['asked']:>5}", "ask" if s["asked"] else None)
        print(f"{s['session_id'][:12]:<14} {_short_ts(s['started_at']):<19}  {s['tool_calls']:>5} {blocked} {asked}  "
              f"{(s['git_branch'] or '-')[:16]:<16} {s['cwd'] or '-'}")
    return 0


def _event_line(e: dict) -> str:
    dec = e["decision"] or ""
    out = e.get("outcome") or ""
    tag = _c(f"{dec:<5}", dec) if dec else " " * 5
    extra = f" ({_c(out, out)})" if out and out not in ("allowed",) else ""
    rule = f" [{e['rule_id']}]" if e["rule_id"] and dec in ("deny", "ask", "error") else ""
    return f"{e['seq']:>6}  {_short_ts(e['ts'])}  {e['event_type']:<18} {tag} {e['summary'] or ''}{rule}{extra}"


def cmd_show(args) -> int:
    conn, _ = _open(args)
    if conn is None:
        return 1
    s = queries.resolve_session(conn, args.session)
    if s is None:
        print(f"No unique session matches {args.session!r}. Try `agent-ledger sessions`.", file=sys.stderr)
        return 1
    print(f"Session   {s['session_id']}")
    print(f"Started   {_short_ts(s['started_at'])} UTC" + (f"   ended {_short_ts(s['ended_at'])} ({s['end_reason']})" if s["ended_at"] else ""))
    print(f"Directory {s['cwd'] or '-'}")
    if s["git_branch"] or s["git_commit"]:
        print(f"Git       {s['git_branch'] or '(detached)'} @ {(s['git_commit'] or '')[:12]}")
    print(f"Calls     {s['tool_calls']} tool calls, {s['blocked']} blocked, {s['asked']} needed approval\n")
    for e in queries.events(conn, session_id=s["session_id"]):
        if args.decision and e["decision"] != args.decision:
            continue
        print(_event_line(e))
    return 0


def cmd_tail(args) -> int:
    conn, _ = _open(args)
    if conn is None:
        return 0
    rows = queries.events(conn, limit=args.n, newest_first=True)
    for e in rows:
        print(_event_line(e))
    last = rows[-1]["seq"] if rows else 0
    if not args.follow:
        return 0
    try:
        while True:
            time.sleep(1)
            for e in queries.events(conn, after_seq=last):
                print(_event_line(e), flush=True)
                last = e["seq"]
    except KeyboardInterrupt:
        return 0


def cmd_report(args) -> int:
    from agent_ledger import report

    conn, cfg = _open(args)
    if conn is None:
        return 1
    session_id = None
    if args.session:
        s = queries.resolve_session(conn, args.session)
        if s is None:
            print(f"No unique session matches {args.session!r}.", file=sys.stderr)
            return 1
        session_id = s["session_id"]
    try:
        since = queries.parse_since(args.since) if args.since else None
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2
    r = report.build_report(conn, session_id=session_id, since=since, key=cfg.hmac_key)
    text = report.RENDERERS[args.format](r)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Wrote {args.format} report to {args.output} ({r['summary']['events']} events, chain "
              f"{'OK' if r['chain']['ok'] else 'BROKEN'})", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0 if r["chain"]["ok"] else 3
