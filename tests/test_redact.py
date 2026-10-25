"""Redaction tests. Every secret below is fake but has a realistic shape."""

import base64
import json
import urllib.parse

import pytest

from agent_ledger.redact import REDACTED, is_secret_path, redact, redact_event_payload

AWS_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
GH_PAT = "github_pat_11ABCDEFG0abcdefghijkl_" + "Z" * 59
ANT = "sk-ant-api03-" + "x7Yz" * 20
OAI = "sk-proj-" + "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z" * 2
SLACK = "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
GOOGLE = "AIza" + "SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"
STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
    "QyNTUxOQAAACDx1Zyq5yC7mF0xk1y0HbXx2f6l3oG6l8P0rTq9wQd1PgAAAJh0bW9yZXN0\n"
    "-----END OPENSSH PRIVATE KEY-----"
)
NPM = "npm_" + "a1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
HF = "hf_" + "AbCdEfGhIjKlMnOpQrStUvWxYz01234567"
GLPAT = "glpat-" + "aB3dE6gH9jK2mN5pQ8sT"

KNOWN = [AWS_ID, AWS_SECRET, GH, GH_PAT, ANT, OAI, SLACK, GOOGLE, STRIPE, JWT, NPM, HF, GLPAT]


def leaked(secret, obj) -> bool:
    return secret in json.dumps(obj, ensure_ascii=False)


@pytest.mark.parametrize("secret", KNOWN)
def test_known_token_formats_bare(secret):
    assert secret not in redact(f"here it is: {secret} ok")


@pytest.mark.parametrize("secret", KNOWN)
def test_known_token_formats_in_nested_structures(secret):
    obj = {"a": [{"b": {"c": f"x {secret}"}}], "tool_response": {"stdout": secret}}
    assert not leaked(secret, redact(obj))


def test_private_key_block():
    out = redact(f"key:\n{PEM}\nend")
    assert "b3BlbnNzaC1rZXkt" not in out and "PRIVATE KEY" in out and REDACTED in out


def test_truncated_private_key_block_without_end_marker():
    out = redact(PEM.rsplit("-----END", 1)[0])
    assert "b3BlbnNzaC1rZXkt" not in out


@pytest.mark.parametrize(
    "text,secret",
    [
        ("DB_PASSWORD=hunter2isgreat", "hunter2isgreat"),
        ("export API_KEY='abc123def456'", "abc123def456"),
        ('password: "s3cr3t-value"', "s3cr3t-value"),
        ('{"client_secret": "zzTopSecret99"}', "zzTopSecret99"),
        ("MY_SERVICE_TOKEN = qwertyuiop12345", "qwertyuiop12345"),
        ("aws_secret_access_key = abcdEFGHijklMNOP", "abcdEFGHijklMNOP"),
        ("mysql -u root -pSup3rS3cret db", "Sup3rS3cret"),
        ("psql --password=Sup3rS3cret2", "Sup3rS3cret2"),
        ("tool --token abcdef0123456789xyz", "abcdef0123456789xyz"),
        ("curl -u admin:Adm1nPass https://x.io", "Adm1nPass"),
        ("curl -H 'Authorization: Bearer abc.def.ghi123456'", "abc.def.ghi123456"),
        ('curl -H "X-API-Key: k3yk3yk3yk3y"', "k3yk3yk3yk3y"),
        ("Cookie: session=abcd1234efgh5678", "abcd1234efgh5678"),
        ("postgres://app:Pa55w0rd!@db.internal:5432/app", "Pa55w0rd!"),
        ("https://user:tok3nvalue@github.com/org/repo.git", "tok3nvalue"),
        ("PASSWORD=1234", "1234"),
    ],
)
def test_assignment_and_flag_forms(text, secret):
    assert secret not in redact(text)


def test_env_dump_output():
    dump = "\n".join(
        [
            "HOME=/Users/me",
            "PATH=/usr/bin:/bin",
            f"OPENAI_API_KEY={OAI}",
            "STRIPE_SECRET=whsec_abcdefghijklmnop",
            "DATABASE_URL=postgres://u:dbpass99@h/db",
        ]
    )
    out = redact(dump)
    assert OAI not in out and "whsec_abcdefghijklmnop" not in out and "dbpass99" not in out
    assert "HOME=/Users/me" in out and "PATH=/usr/bin:/bin" in out


def test_secret_keys_in_dicts_redact_values():
    obj = {"password": "plainpass", "nested": {"apiKey": "k-123456", "Authorization": "Basic Zm9vOmJhcg=="}}
    out = redact(obj)
    assert not leaked("plainpass", out)
    assert not leaked("k-123456", out)
    assert not leaked("Zm9vOmJhcg==", out)


def test_secret_hidden_in_dict_key():
    out = redact({f"weird {GH}": 1})
    assert not leaked(GH, out)


def test_url_encoded_secret():
    enc = urllib.parse.quote(f"token={GH}")
    assert GH not in urllib.parse.unquote(json.dumps(redact(f"https://x.io/cb?{enc}")))
    assert "a1B2c3D4e5F6g7H8i9J0" not in redact(f"q={urllib.parse.quote(ANT)}")


def test_zero_width_characters_do_not_hide_secret():
    sneaky = GH[:10] + "​" + GH[10:]
    out = redact(f"x {sneaky} y")
    assert GH not in out.replace("​", "")
    assert GH[12:30] not in out


def test_fullwidth_lookalikes_are_normalised():
    sneaky = "ｓｋ-ant-api03-" + "x7Yz" * 20  # fullwidth "sk"
    out = redact(sneaky)
    assert "x7Yzx7Yzx7Yz" not in out


def test_high_entropy_base64_blob_is_redacted():
    blob = base64.b64encode(b"OPENAI_API_KEY=" + OAI.encode() + b"\nDB_PASS=hunter2hunter2\n").decode()
    assert blob[:40] not in redact(f"echo {blob} | base64 -d")


def test_secret_split_across_lines_by_shell_continuation_is_still_flagged_by_entropy():
    # A key split with a line continuation: each half is still long and random.
    key = "sk-ant-api03-Qm7vX2pL9sR4tY8wK1nB6cF3hJ0dZ5gA" + "Tq8Lm2Xv7Rp4Ws9Ky1Nb6Cf3Hj0Dz5Ga"
    half1, half2 = key[:45], key[45:]
    out = redact(f"echo {half1}\\\n{half2}")
    assert half1[13:] not in out and half2 not in out


@pytest.mark.parametrize(
    "benign",
    [
        "git commit -m 'fix the tokenizer bug'",
        "/Users/someone/Projects/AgentLedger/agent_ledger/policy_engine_module.py",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256 hex
        "9f2c1a7b8e4d3c6f5a0b1e2d3c4f5a6b7c8d9e0f",  # git sha
        "pytest -q tests/test_policy.py -k bypass",
        "550e8400-e29b-41d4-a716-446655440000",
    ],
)
def test_benign_strings_survive(benign):
    assert redact(benign) == benign


def test_non_string_scalars_untouched():
    assert redact({"n": 5, "b": True, "x": None, "f": 1.5}) == {"n": 5, "b": True, "x": None, "f": 1.5}


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/p/.env", True),
        ("/p/.env.local", True),
        ("/p/config/.env.production", True),
        ("/home/u/.ssh/id_rsa", True),
        ("/home/u/.ssh/id_ed25519", True),
        ("/p/certs/server.pem", True),
        ("/p/certs/tls.key", True),
        ("/home/u/.aws/credentials", True),
        ("/home/u/.netrc", True),
        ("/home/u/.npmrc", True),
        ("/home/u/.pypirc", True),
        ("/p/src/environment.py", False),
        ("/p/README.md", False),
        ("/home/u/.ssh/id_rsa.pub", False),
    ],
)
def test_is_secret_path(path, expected):
    assert is_secret_path(path) is expected


def test_secret_file_content_is_dropped_entirely():
    payload = {
        "tool_name": "Read",
        "tool_input": {"file_path": "/p/.env"},
        "tool_response": {"file": {"content": "HARMLESS_LOOKING=value123\nX=y"}},
    }
    out = redact_event_payload(payload)
    assert not leaked("value123", out)


def test_secret_file_write_and_edit_inputs_dropped():
    for ti in (
        {"file_path": "/p/.env", "content": "FOO=barbazqux"},
        {"file_path": "/p/.env", "old_string": "FOO=a", "new_string": "FOO=barbazqux"},
    ):
        out = redact_event_payload({"tool_name": "Write", "tool_input": ti})
        assert not leaked("barbazqux", out)
        assert out["tool_input"]["file_path"] == "/p/.env"


def test_secret_in_edit_diff_of_normal_file():
    payload = {
        "tool_name": "Edit",
        "tool_input": {"file_path": "/p/app.py", "old_string": "KEY = ''", "new_string": f"KEY = '{STRIPE}'"},
    }
    assert not leaked(STRIPE, redact_event_payload(payload))


def test_secret_in_prompt():
    assert not leaked(ANT, redact_event_payload({"prompt": f"use this key {ANT} please"}))


def test_redact_is_idempotent():
    once = redact(f"API_KEY={GH}")
    assert redact(once) == once
