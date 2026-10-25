"""Audit report: one data model (`build_report`) rendered as JSON, Markdown or self-contained HTML."""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone

from agent_ledger import __version__, queries, store

DISCLAIMER = (
    "agent-ledger supports evidence for the control areas below. It does not by itself establish "
    "conformity with any regulation or standard; that depends on how it is deployed, reviewed and "
    "combined with your other controls."
)

CONTROL_MAPPING = [
    {
        "framework": "EU AI Act",
        "control": "Article 12 - Record-keeping",
        "evidence": "Automatic, timestamped logging of every agent prompt, tool call, policy decision and "
                    "session start/end, in a tamper-evident hash chain with retained policy versions.",
        "statement": "Supports evidence for automatic event logging and traceability of the AI system's operation.",
    },
    {
        "framework": "EU AI Act",
        "control": "Article 14 - Human oversight",
        "evidence": "Risky actions are paused for a human decision ('ask'), dangerous ones are blocked "
                    "('deny'), and the report records which actions were approved, denied or blocked.",
        "statement": "Supports evidence for the ability of people to oversee, intervene in and override the "
                     "agent's actions.",
    },
    {
        "framework": "NIST AI RMF 1.0",
        "control": "GOVERN",
        "evidence": "A written, versioned policy (rules with ids, severities and reasons); each event "
                    "stores the hash of the policy in force; repo policies must be explicitly trusted.",
        "statement": "Supports evidence for documented policies and accountability for agent behaviour.",
    },
    {
        "framework": "NIST AI RMF 1.0",
        "control": "MANAGE",
        "evidence": "Risk treatment at run time (allow / ask / deny), a ranked list of the riskiest events, "
                    "and an audit trail for post-incident review.",
        "statement": "Supports evidence for responding to and monitoring identified AI risks.",
    },
    {
        "framework": "ISO/IEC 42001:2023",
        "control": "Clause 8 - Operation (operational planning and control)",
        "evidence": "Operational controls enforced before each agent action, with logged outcomes and "
                    "integrity verification of the log.",
        "statement": "Supports evidence for operational control of AI system use and its event logging.",
    },
]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_report(conn, session_id: str | None = None, since: str | None = None, key: bytes | None = None,
                 risky_limit: int = 10) -> dict:
    rows = queries.events(conn, session_id=session_id, since=since)
    session_ids = sorted({r["session_id"] for r in rows})
    sessions = [s for s in (queries.resolve_session(conn, sid) for sid in session_ids) if s]
    pre = [r for r in rows if r["event_type"] == "PreToolUse"]
    outcomes = Counter(r["outcome"] for r in pre)
    decisions = Counter(r["decision"] or "none" for r in pre)
    tools = Counter(r["tool_name"] for r in pre if r["tool_name"])
    files = sorted({
        queries.payload(r).get("tool_input", {}).get("file_path")
        for r in pre
        if r["tool_name"] in queries.FILE_TOOLS and r["outcome"] in ("allowed", "approved", "ran")
    } - {None})
    commands = sum(1 for r in pre if r["tool_name"] == "Bash" and r["outcome"] in ("allowed", "approved", "ran"))
    risky = sorted(
        (r for r in pre if r["decision"] in ("deny", "ask", "error") or queries.SEVERITY_RANK.get(r["severity"], 0) >= 3),
        key=queries.risk_key, reverse=True,
    )[:risky_limit]
    policies: dict[str, dict] = {}
    for r in rows:
        h = r["policy_hash"] or "none"
        p = policies.setdefault(h, {"hash": h, "first_seen": r["ts"], "last_seen": r["ts"], "events": 0})
        p["last_seen"] = r["ts"]
        p["events"] += 1
    v = store.verify(conn, key=key)
    return {
        "title": "agent-ledger audit report",
        "generated_at": _now(),
        "generator": f"agent-ledger {__version__}",
        "scope": {"session": session_id, "since": since, "sessions": session_ids},
        "summary": {
            "sessions": len(session_ids),
            "events": len(rows),
            "prompts": sum(1 for r in rows if r["event_type"] == "UserPromptSubmit"),
            "tool_calls": len(pre),
            "allowed": outcomes.get("allowed", 0),
            "approved": outcomes.get("approved", 0),
            "denied_by_user": outcomes.get("denied", 0),
            "blocked": outcomes.get("blocked", 0),
            "not_run": outcomes.get("not run", 0),
            "errors": outcomes.get("error", 0),
            "decisions": dict(decisions),
            "tools": dict(tools.most_common()),
            "files_changed": files,
            "commands_run": commands,
        },
        "riskiest": [_event_view(r) for r in risky],
        "sessions": sessions,
        "policies": list(policies.values()),
        "chain": {
            "ok": v.ok, "checked": v.checked, "head_hash": v.head_hash, "first_bad_seq": v.first_bad_seq,
            "reason": v.reason, "hmac": bool(key),
            "scope_note": "The whole ledger is verified, not only the events in this report.",
        },
        "events": [_event_view(r) for r in rows],
        "control_mapping": CONTROL_MAPPING,
        "disclaimer": DISCLAIMER,
    }


def _event_view(r: dict) -> dict:
    return {k: r.get(k) for k in ("seq", "ts", "session_id", "event_type", "tool_name", "summary", "decision",
                                  "rule_id", "severity", "reason", "outcome", "policy_hash")}


# ---------------------------------------------------------------- JSON / Markdown

def render_json(r: dict) -> str:
    return json.dumps(r, indent=2, ensure_ascii=False, default=str)


def _md(s) -> str:
    return "" if s is None else str(s).replace("|", "\\|").replace("\n", " ")


def render_md(r: dict) -> str:
    s, c = r["summary"], r["chain"]
    out = [f"# {r['title']}", "", f"Generated {r['generated_at']} by {r['generator']}.", ""]
    scope = r["scope"]
    out.append(f"Scope: {'session ' + scope['session'] if scope['session'] else 'events since ' + scope['since'] if scope['since'] else 'entire ledger'} "
               f"({s['sessions']} session(s)).")
    out += ["", "## Summary", "",
            f"The agent made **{s['tool_calls']} tool calls** and received **{s['prompts']} prompts** "
            f"({s['events']} recorded events). It ran {s['commands_run']} shell command(s) and changed "
            f"{len(s['files_changed'])} file(s).", "",
            "| Outcome | Count |", "|---|---|",
            f"| Allowed by policy | {s['allowed']} |", f"| Approved by a person | {s['approved']} |",
            f"| Denied by a person | {s['denied_by_user']} |", f"| Blocked by policy | {s['blocked']} |",
            f"| Asked but never ran | {s['not_run']} |", f"| Policy errors | {s['errors']} |", ""]
    if s["tools"]:
        out.append("Tools used: " + ", ".join(f"{k} ({v})" for k, v in s["tools"].items()) + ".")
        out.append("")
    if s["files_changed"]:
        out += ["Files changed:", ""] + [f"- `{f}`" for f in s["files_changed"]] + [""]
    out += ["## Riskiest events", ""]
    if r["riskiest"]:
        out += ["| Seq | Time | Severity | Decision | Outcome | Rule | Action |", "|---|---|---|---|---|---|---|"]
        out += [f"| {e['seq']} | {e['ts']} | {_md(e['severity'])} | {_md(e['decision'])} | {_md(e['outcome'])} | "
                f"{_md(e['rule_id'])} | {_md(e['summary'])} |" for e in r["riskiest"]]
    else:
        out.append("No risky events.")
    out += ["", "## Policy versions", "", "| Policy hash | First seen | Last seen | Events |", "|---|---|---|---|"]
    out += [f"| `{p['hash']}` | {p['first_seen']} | {p['last_seen']} | {p['events']} |" for p in r["policies"]]
    out += ["", "## Hash-chain verification", ""]
    if c["ok"]:
        out.append(f"**OK.** {c['checked']} events verified; chain intact. Head hash: `{c['head_hash']}`"
                   + (" (HMAC-keyed)." if c["hmac"] else "."))
    else:
        where = f" at seq {c['first_bad_seq']}" if c["first_bad_seq"] else ""
        out.append(f"**BROKEN{where}:** {c['reason']}. {c['checked']} events verified before the problem.")
    out += ["", c["scope_note"], "", "## Sessions", "",
            "| Session | Started | Ended | Directory | Branch | Commit | Tool calls | Blocked | Asked |",
            "|---|---|---|---|---|---|---|---|---|"]
    out += [f"| `{x['session_id']}` | {x['started_at']} | {x['ended_at'] or ''} | {_md(x['cwd'])} | {_md(x['git_branch'])} | "
            f"{_md((x['git_commit'] or '')[:12])} | {x['tool_calls']} | {x['blocked']} | {x['asked']} |" for x in r["sessions"]]
    out += ["", "## All events", "", "| Seq | Time | Session | Event | Tool | Decision | Outcome | Rule | Summary |",
            "|---|---|---|---|---|---|---|---|---|"]
    out += [f"| {e['seq']} | {e['ts']} | {_md(e['session_id'][:8])} | {e['event_type']} | {_md(e['tool_name'])} | "
            f"{_md(e['decision'])} | {_md(e['outcome'])} | {_md(e['rule_id'])} | {_md(e['summary'])} |" for e in r["events"]]
    out += ["", "## Appendix: control mapping", "", r["disclaimer"], "",
            "| Framework | Control area | What agent-ledger records | Statement |", "|---|---|---|---|"]
    out += [f"| {m['framework']} | {m['control']} | {_md(m['evidence'])} | {_md(m['statement'])} |" for m in r["control_mapping"]]
    out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------- HTML

_CSS = """
:root{--bg:#fbfaf7;--fg:#1d1b18;--muted:#6b665d;--line:#e4e0d6;--card:#fff;--deny:#b42318;--ask:#b54708;--allow:#067647;--accent:#3a3530}
@media (prefers-color-scheme:dark){:root{--bg:#161513;--fg:#ece8df;--muted:#a39d91;--line:#2f2c27;--card:#1e1c19;--deny:#f97066;--ask:#fdb022;--allow:#47cd89;--accent:#d6cfc2}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 ui-sans-serif,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:40px 20px 80px}h1{font:600 28px/1.2 ui-serif,Georgia,serif;margin:0 0 4px}
h2{font:600 19px/1.3 ui-serif,Georgia,serif;margin:40px 0 12px;padding-top:12px;border-top:1px solid var(--line)}
.muted{color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}.card b{display:block;font-size:26px;font-variant-numeric:tabular-nums}
table{width:100%;border-collapse:collapse;font-size:13px;background:var(--card)}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.03em}.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px}
code,.mono{font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.b{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid currentColor}
.deny,.error,.blocked,.critical{color:var(--deny)}.ask,.high,.medium,.not-run,.denied{color:var(--ask)}.allow,.allowed,.approved,.ok{color:var(--allow)}
.verdict{padding:14px 16px;border-radius:10px;border:1px solid currentColor;margin:8px 0}
@media print{body{background:#fff}main{padding:0}.wrap{border:none}}
"""


def _e(s) -> str:
    return html.escape("" if s is None else str(s), quote=True)


def _badge(v) -> str:
    return f'<span class="b {_e(str(v).replace(" ", "-"))}">{_e(v)}</span>' if v else ""


def render_html(r: dict) -> str:
    s, c = r["summary"], r["chain"]
    scope = r["scope"]
    scope_txt = f"session {scope['session']}" if scope["session"] else f"events since {scope['since']}" if scope["since"] else "entire ledger"
    cards = [("Tool calls", s["tool_calls"]), ("Blocked", s["blocked"]), ("Approved by a person", s["approved"]),
             ("Denied by a person", s["denied_by_user"]), ("Asked, never ran", s["not_run"]), ("Prompts", s["prompts"])]
    h = ["<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
         "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
         f"<title>agent-ledger audit report</title><style>{_CSS}</style></head><body><main>",
         f"<h1>Audit report</h1><p class=\"muted\">Generated {_e(r['generated_at'])} by {_e(r['generator'])} · "
         f"Scope: {_e(scope_txt)} ({s['sessions']} session(s), {s['events']} events)</p>"]
    verdict_cls = "ok" if c["ok"] else "deny"
    verdict = (f"Hash chain intact: {c['checked']} events verified. Head hash <code>{_e(c['head_hash'])}</code>"
               if c["ok"] else f"Hash chain BROKEN{(' at seq ' + str(c['first_bad_seq'])) if c['first_bad_seq'] else ''}: {_e(c['reason'])}")
    h.append(f'<div class="verdict {verdict_cls}">{verdict}</div>')
    h.append('<div class="cards">' + "".join(f'<div class="card"><b>{v}</b><span class="muted">{_e(k)}</span></div>' for k, v in cards) + "</div>")
    h.append(f"<h2>Summary</h2><p>The agent made <b>{s['tool_calls']}</b> tool calls, ran {s['commands_run']} shell command(s) "
             f"and changed {len(s['files_changed'])} file(s). Tools used: "
             + (_e(", ".join(f"{k} ({v})" for k, v in s["tools"].items())) or "none") + ".</p>")
    if s["files_changed"]:
        h.append("<details><summary>Files changed</summary><ul>" + "".join(f"<li><code>{_e(f)}</code></li>" for f in s["files_changed"]) + "</ul></details>")
    h.append("<h2>Riskiest events</h2>")
    if r["riskiest"]:
        h.append('<div class="wrap"><table><tr><th>Seq</th><th>Time</th><th>Severity</th><th>Decision</th><th>Outcome</th><th>Rule</th><th>Action</th></tr>')
        h += [f"<tr><td>{e['seq']}</td><td class=mono>{_e(e['ts'])}</td><td>{_badge(e['severity'])}</td><td>{_badge(e['decision'])}</td>"
              f"<td>{_badge(e['outcome'])}</td><td class=mono>{_e(e['rule_id'])}</td><td class=mono>{_e(e['summary'])}</td></tr>" for e in r["riskiest"]]
        h.append("</table></div>")
    else:
        h.append("<p class=muted>No risky events.</p>")
    h.append('<h2>Policy versions</h2><div class="wrap"><table><tr><th>Policy hash</th><th>First seen</th><th>Last seen</th><th>Events</th></tr>')
    h += [f"<tr><td class=mono>{_e(p['hash'])}</td><td class=mono>{_e(p['first_seen'])}</td><td class=mono>{_e(p['last_seen'])}</td><td>{p['events']}</td></tr>" for p in r["policies"]]
    h.append("</table></div>")
    h.append(f"<h2>Hash-chain verification</h2><p>{verdict}.</p><p class=muted>{_e(c['scope_note'])}"
             + (" Rows are HMAC-keyed." if c["hmac"] else "") + "</p>")
    h.append('<h2>Sessions</h2><div class="wrap"><table><tr><th>Session</th><th>Started</th><th>Ended</th><th>Directory</th><th>Branch</th><th>Commit</th><th>Calls</th><th>Blocked</th><th>Asked</th></tr>')
    h += [f"<tr><td class=mono>{_e(x['session_id'])}</td><td class=mono>{_e(x['started_at'])}</td><td class=mono>{_e(x['ended_at'])}</td>"
          f"<td class=mono>{_e(x['cwd'])}</td><td>{_e(x['git_branch'])}</td><td class=mono>{_e((x['git_commit'] or '')[:12])}</td>"
          f"<td>{x['tool_calls']}</td><td>{x['blocked']}</td><td>{x['asked']}</td></tr>" for x in r["sessions"]]
    h.append("</table></div>")
    h.append('<h2>All events</h2><div class="wrap"><table><tr><th>Seq</th><th>Time</th><th>Session</th><th>Event</th><th>Tool</th><th>Decision</th><th>Outcome</th><th>Rule</th><th>Summary</th></tr>')
    h += [f"<tr><td>{e['seq']}</td><td class=mono>{_e(e['ts'])}</td><td class=mono>{_e(e['session_id'][:8])}</td><td>{_e(e['event_type'])}</td>"
          f"<td>{_e(e['tool_name'])}</td><td>{_badge(e['decision'])}</td><td>{_badge(e['outcome'])}</td><td class=mono>{_e(e['rule_id'])}</td>"
          f"<td class=mono>{_e(e['summary'])}</td></tr>" for e in r["events"]]
    h.append("</table></div>")
    h.append(f"<h2>Appendix: control mapping</h2><p>{_e(r['disclaimer'])}</p>")
    h.append('<div class="wrap"><table><tr><th>Framework</th><th>Control area</th><th>What agent-ledger records</th><th>Statement</th></tr>')
    h += [f"<tr><td>{_e(m['framework'])}</td><td>{_e(m['control'])}</td><td>{_e(m['evidence'])}</td><td>{_e(m['statement'])}</td></tr>" for m in r["control_mapping"]]
    h.append("</table></div></main></body></html>")
    return "\n".join(h)


RENDERERS = {"json": render_json, "md": render_md, "html": render_html}
