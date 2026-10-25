"""Hash chain over ledger rows.

row_hash = SHA-256(prev_hash || canonical_json(fields)), or HMAC-SHA-256 with a key.
Any edit, deletion, insertion or reordering of rows breaks a link that verify finds.
Someone who can rewrite the whole database can recompute the whole chain; anchor the
head hash elsewhere (or use an HMAC key the agent cannot read) to defend against that.
"""

from __future__ import annotations

import json

try:  # the builtin module avoids loading OpenSSL via hashlib (~2 ms on the hot path)
    from _sha2 import sha256 as _sha256  # Python 3.12+
except ImportError:  # pragma: no cover
    try:
        from _sha256 import sha256 as _sha256  # Python 3.11
    except ImportError:
        from hashlib import sha256 as _sha256

GENESIS = "0" * 64


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(prev_hash: str, fields: dict, key: bytes | None = None) -> str:
    data = (prev_hash + canonical_json(fields)).encode("utf-8")
    if key:
        import hashlib
        import hmac

        return hmac.new(key, data, hashlib.sha256).hexdigest()
    return _sha256(data).hexdigest()


class VerifyResult:
    __slots__ = ("ok", "checked", "head_hash", "first_bad_seq", "reason")

    def __init__(self, ok: bool, checked: int, head_hash: str, first_bad_seq: int | None = None, reason: str = ""):
        self.ok, self.checked, self.head_hash = ok, checked, head_hash
        self.first_bad_seq, self.reason = first_bad_seq, reason


def verify_rows(
    rows, fields_of, key: bytes | None = None
) -> VerifyResult:
    expected_prev = GENESIS
    last_seq = 0
    checked = 0
    for row in rows:
        seq = row["seq"]
        if seq != last_seq + 1:
            return VerifyResult(False, checked, expected_prev, seq, f"sequence gap: expected {last_seq + 1}, found {seq}")
        if row["prev_hash"] != expected_prev:
            return VerifyResult(False, checked, expected_prev, seq, "prev_hash does not link to the previous row")
        if compute_hash(row["prev_hash"], fields_of(row), key) != row["row_hash"]:
            return VerifyResult(False, checked, expected_prev, seq, "row hash mismatch (row content was changed)")
        expected_prev = row["row_hash"]
        last_seq = seq
        checked += 1
    return VerifyResult(True, checked, expected_prev)
