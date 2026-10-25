from agent_ledger.chain import GENESIS, canonical_json, compute_hash, verify_rows


def make_rows(n, key=None):
    rows, prev = [], GENESIS
    for i in range(1, n + 1):
        fields = {"seq": i, "ts": f"2026-01-01T00:00:0{i}Z", "event_type": "PreToolUse", "summary": f"e{i}"}
        h = compute_hash(prev, fields, key) if key else compute_hash(prev, fields)
        rows.append({**fields, "prev_hash": prev, "row_hash": h})
        prev = h
    return rows


def strip(row):
    return {k: v for k, v in row.items() if k not in ("prev_hash", "row_hash")}


def test_canonical_json_is_order_independent_and_compact():
    assert canonical_json({"b": 1, "a": [1, "é"]}) == canonical_json({"a": [1, "é"], "b": 1})
    assert canonical_json({"a": 1}) == '{"a":1}'


def test_hash_depends_on_prev_and_fields():
    f = {"seq": 1, "x": "y"}
    assert compute_hash(GENESIS, f) != compute_hash("1" * 64, f)
    assert compute_hash(GENESIS, f) != compute_hash(GENESIS, {**f, "x": "z"})
    assert len(compute_hash(GENESIS, f)) == 64


def test_hmac_key_changes_hash():
    f = {"seq": 1}
    assert compute_hash(GENESIS, f, b"k") != compute_hash(GENESIS, f)


def test_verify_ok():
    rows = make_rows(5)
    r = verify_rows(rows, strip)
    assert r.ok and r.checked == 5 and r.head_hash == rows[-1]["row_hash"]


def test_verify_detects_edit():
    rows = make_rows(5)
    rows[2]["summary"] = "tampered"
    r = verify_rows(rows, strip)
    assert not r.ok and r.first_bad_seq == 3 and "hash" in r.reason


def test_verify_detects_delete():
    rows = make_rows(5)
    del rows[2]
    r = verify_rows(rows, strip)
    assert not r.ok and r.first_bad_seq == 4


def test_verify_detects_reorder():
    rows = make_rows(5)
    rows[1], rows[2] = rows[2], rows[1]
    r = verify_rows(rows, strip)
    assert not r.ok and r.first_bad_seq in (2, 3)


def test_verify_detects_insert_with_recomputed_own_hash():
    rows = make_rows(4)
    fake = {"seq": 3, "ts": "x", "event_type": "PreToolUse", "summary": "forged"}
    fake_hash = compute_hash(rows[1]["row_hash"], fake)
    rows.insert(2, {**fake, "prev_hash": rows[1]["row_hash"], "row_hash": fake_hash})
    r = verify_rows(rows, strip)
    assert not r.ok


def test_verify_detects_rewritten_prev_hash_field():
    rows = make_rows(3)
    rows[1]["prev_hash"] = "f" * 64
    r = verify_rows(rows, strip)
    assert not r.ok and r.first_bad_seq == 2


def test_verify_with_wrong_hmac_key_fails():
    rows = make_rows(3, key=b"secret")
    assert verify_rows(rows, strip, key=b"secret").ok
    assert not verify_rows(rows, strip, key=b"other").ok


def test_verify_empty():
    r = verify_rows([], strip)
    assert r.ok and r.checked == 0 and r.head_hash == GENESIS
