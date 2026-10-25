"""`agent-ledger serve`: a read-only local dashboard.

Safety properties (tested in tests/test_server.py):
- binds to 127.0.0.1 only; requests whose Host header is not localhost/127.0.0.1 are
  refused (blocks DNS-rebinding pages from reading the log);
- GET/HEAD only, everything else is 405; there is no endpoint that writes;
- the database is opened with SQLite's read-only URI mode for every request;
- the page is one static file with no external resources, served with a strict CSP;
  logged data reaches the page only as JSON and is inserted with textContent.
"""

from __future__ import annotations

import difflib
import json
import re
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from agent_ledger import queries, store

STATIC = Path(__file__).with_name("static") / "dashboard.html"
DIFF_MAX_LINES = 400
_SESSION_PATH = re.compile(r"^/api/session/([^/]{1,200})$")


def _diff(tool: str, ti: dict) -> list[str] | None:
    def lines(s):
        return (s if isinstance(s, str) else "").splitlines()

    path = ti.get("file_path") or ti.get("notebook_path") or "file"
    if tool == "Edit":
        d = list(difflib.unified_diff(lines(ti.get("old_string")), lines(ti.get("new_string")), path, path, lineterm="", n=2))
    elif tool == "MultiEdit" and isinstance(ti.get("edits"), list):
        d = []
        for e in ti["edits"]:
            if isinstance(e, dict):
                d += list(difflib.unified_diff(lines(e.get("old_string")), lines(e.get("new_string")), path, path, lineterm="", n=2))
    elif tool == "Write":
        body = lines(ti.get("content"))
        d = [f"+++ {path}", f"@@ new content, {len(body)} lines @@"] + ["+" + x for x in body]
    elif tool == "NotebookEdit":
        d = ["@@ notebook cell @@"] + ["+" + x for x in lines(ti.get("new_source"))]
    else:
        return None
    if len(d) > DIFF_MAX_LINES:
        d = d[:DIFF_MAX_LINES] + [f"… {len(d) - DIFF_MAX_LINES} more lines"]
    return d


def _event_json(e: dict) -> dict:
    p = queries.payload(e)
    ti = p.get("tool_input") if isinstance(p.get("tool_input"), dict) else {}
    out = {k: e.get(k) for k in ("seq", "ts", "event_type", "tool_name", "tool_use_id", "summary", "decision",
                                 "rule_id", "severity", "reason", "outcome", "policy_hash")}
    out["detail"] = p
    if e["event_type"] == "PreToolUse" and e.get("tool_name"):
        out["diff"] = _diff(e["tool_name"], ti)
    if e["event_type"] == "UserPromptSubmit":
        out["prompt"] = p.get("prompt")
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = "agent-ledger"
    sys_version = ""
    db_path: Path
    hmac_key: bytes | None = None

    # --- plumbing
    def log_message(self, fmt, *args):  # quiet by default
        pass

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        port = self.server.server_address[1]
        return host in (f"127.0.0.1:{port}", f"localhost:{port}")

    def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, status=200):
        self._send(status, json.dumps(obj, default=str).encode("utf-8"), "application/json; charset=utf-8")

    def _deny_method(self):
        self._send(405, b"read-only: only GET is supported\n", "text/plain; charset=utf-8", {"Allow": "GET, HEAD"})

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = _deny_method

    def do_HEAD(self):
        self.do_GET()

    # --- routes
    def do_GET(self):
        if not self._host_ok():
            self._send(403, b"forbidden host\n", "text/plain; charset=utf-8")
            return
        url = urlsplit(self.path)
        path = unquote(url.path)
        try:
            if path in ("/", "/index.html"):
                return self._page()
            if not path.startswith("/api/"):
                return self._send(404, b"not found\n", "text/plain; charset=utf-8")
            if not self.db_path.exists():
                return self._json({"error": "no ledger yet"}, 404)
            conn = store.connect(self.db_path, readonly=True)
            try:
                return self._api(conn, path, parse_qs(url.query))
            finally:
                conn.close()
        except Exception as e:  # never leak a traceback page
            return self._json({"error": type(e).__name__}, 500)

    def _page(self):
        nonce = secrets.token_urlsafe(16)
        html = STATIC.read_text("utf-8").replace("{{NONCE}}", nonce)
        csp = (f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; "
               "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self._send(200, html.encode("utf-8"), "text/html; charset=utf-8", {"Content-Security-Policy": csp})

    def _api(self, conn, path: str, qs: dict):
        if path == "/api/sessions":
            return self._json(queries.list_sessions(conn, limit=500))
        if path == "/api/risky":
            rows = queries.events(conn)
            risky = sorted((r for r in rows if r["event_type"] == "PreToolUse" and r["decision"] in ("deny", "ask", "error")),
                           key=queries.risk_key, reverse=True)[:50]
            return self._json([dict(_event_json(r), session_id=r["session_id"]) for r in risky])
        if path == "/api/verify":
            v = store.verify(conn, key=self.hmac_key)
            return self._json({"ok": v.ok, "checked": v.checked, "head_hash": v.head_hash,
                               "first_bad_seq": v.first_bad_seq, "reason": v.reason})
        m = _SESSION_PATH.match(path)
        if m:
            s = queries.resolve_session(conn, m.group(1))
            if s is None:
                return self._json({"error": "unknown session"}, 404)
            evs = [_event_json(e) for e in queries.events(conn, session_id=s["session_id"])]
            return self._json({"session": s, "events": evs})
        return self._json({"error": "not found"}, 404)


def make_server(db_path, port: int = 8765, hmac_key: bytes | None = None) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"db_path": Path(db_path), "hmac_key": hmac_key})
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    srv.daemon_threads = True
    return srv


def serve(db_path, port: int = 8765, hmac_key: bytes | None = None, open_browser: bool = False) -> int:
    srv = make_server(db_path, port, hmac_key)
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    print(f"agent-ledger dashboard (read-only) at {url}  -  Ctrl+C to stop")
    if open_browser:
        import webbrowser

        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0
