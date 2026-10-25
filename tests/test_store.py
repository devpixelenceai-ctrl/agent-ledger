import multiprocessing as mp
import os
import sqlite3
import stat

from agent_ledger import store


def row(session="s1", event_type="PreToolUse", **kw):
    base = {
        "ts": "2026-01-01T00:00:00.000000Z",
        "agent": "claude-code",
        "session_id": session,
        "event_type": event_type,
        "tool_name": "Bash",
        "tool_use_id": "t1",
        "summary": "Bash: ls",
        "payload": "{}",
        "decision": None,
        "rule_id": None,
        "severity": None,
        "reason": None,
        "policy_hash": "none",
    }
    base.update(kw)
    return base


def test_append_and_verify(tmp_path):
    conn = store.connect(tmp_path / "l.db")
    for i in range(5):
        seq, h = store.append(conn, row(summary=f"e{i}"))
        assert seq == i + 1 and len(h) == 64
    r = store.verify(conn)
    assert r.ok and r.checked == 5


def test_wal_mode_and_file_permissions(tmp_path):
    db = tmp_path / "sub" / "l.db"
    conn = store.connect(db)
    store.append(conn, row())
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert stat.S_IMODE(os.stat(db).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(db.parent).st_mode) == 0o700


def _tamper(db, sql):
    c = sqlite3.connect(db)
    c.execute(sql)
    c.commit()
    c.close()


def test_verify_detects_tampering_via_sqlite(tmp_path):
    db = tmp_path / "l.db"
    conn = store.connect(db)
    for i in range(5):
        store.append(conn, row(summary=f"e{i}"))
    conn.close()
    _tamper(db, "UPDATE events SET decision='allow' WHERE seq=3")
    r = store.verify(store.connect(db))
    assert not r.ok and r.first_bad_seq == 3


def test_verify_detects_deleted_row(tmp_path):
    db = tmp_path / "l.db"
    conn = store.connect(db)
    for i in range(5):
        store.append(conn, row(summary=f"e{i}"))
    conn.close()
    _tamper(db, "DELETE FROM events WHERE seq=2")
    r = store.verify(store.connect(db))
    assert not r.ok and r.first_bad_seq == 3


def test_hmac_key_is_used(tmp_path):
    conn = store.connect(tmp_path / "l.db")
    store.append(conn, row(), key=b"k1")
    assert store.verify(conn, key=b"k1").ok
    assert not store.verify(conn).ok


def test_session_bookkeeping(tmp_path):
    conn = store.connect(tmp_path / "l.db")
    store.append(conn, row(event_type="SessionStart", tool_name=None), session_meta={
        "cwd": "/p", "git_branch": "main", "git_commit": "abc", "model": "m", "transcript_path": "/t"})
    store.append(conn, row(decision="allow"))
    store.append(conn, row(decision="deny"))
    store.append(conn, row(decision="ask"))
    store.append(conn, row(event_type="PostToolUse"))
    store.append(conn, row(event_type="SessionEnd", tool_name=None), session_meta={"end_reason": "other"})
    s = store.get_session(conn, "s1")
    assert s["cwd"] == "/p" and s["git_branch"] == "main" and s["git_commit"] == "abc"
    assert s["tool_calls"] == 3 and s["blocked"] == 1 and s["asked"] == 1
    assert s["ended_at"] and s["end_reason"] == "other"


def test_session_created_for_mid_session_install(tmp_path):
    conn = store.connect(tmp_path / "l.db")
    store.append(conn, row(session="late"))
    s = store.get_session(conn, "late")
    assert s["started_at"] and s["tool_calls"] == 1


def test_resume_does_not_reset_git_info(tmp_path):
    conn = store.connect(tmp_path / "l.db")
    store.append(conn, row(event_type="SessionStart"), session_meta={"git_branch": "main", "git_commit": "a1"})
    store.append(conn, row(event_type="SessionStart"), session_meta={"git_branch": "feature", "git_commit": "b2"})
    s = store.get_session(conn, "s1")
    assert s["git_branch"] == "main" and s["git_commit"] == "a1"


def test_readonly_connection_cannot_write(tmp_path):
    db = tmp_path / "l.db"
    store.append(store.connect(db), row())
    ro = store.connect(db, readonly=True)
    try:
        ro.execute("DELETE FROM events")
        raise AssertionError("write succeeded on read-only connection")
    except sqlite3.OperationalError:
        pass


def _writer(db, n, idx):
    conn = store.connect(db)
    for i in range(n):
        store.append(conn, row(session=f"s{idx}", summary=f"w{idx}-{i}"))


def test_parallel_writers_keep_chain_linear(tmp_path):
    db = tmp_path / "l.db"
    store.connect(db).close()
    ctx = mp.get_context("spawn")
    procs = [ctx.Process(target=_writer, args=(db, 10, i)) for i in range(20)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
        assert p.exitcode == 0
    conn = store.connect(db)
    r = store.verify(conn)
    assert r.ok and r.checked == 200
    seqs = [x[0] for x in conn.execute("SELECT seq FROM events ORDER BY seq")]
    assert seqs == list(range(1, 201))
