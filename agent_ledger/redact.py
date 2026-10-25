"""Secret redaction. Everything the ledger stores goes through `redact_event_payload`.

Layers, in order:
1. Normalise: strip zero-width characters, NFKC-fold look-alikes, percent-decode.
2. Known token formats (AWS, GitHub, Anthropic, OpenAI, Slack, Google, Stripe, JWT, PEM, ...).
3. Structural forms: URL credentials, auth headers, CLI flags, KEY=value assignments.
4. High-entropy strings that look like base64/random keys.
5. Whole-content drop for secret files (.env, keys, credential stores).

It is best-effort: an agent that deliberately encodes a secret (e.g. ROT13, splitting into
short pieces) can get it past any pattern-based redactor. See docs/threat-model.md.
"""

from __future__ import annotations

import math
import re
import unicodedata

REDACTED = "[REDACTED]"
SECRET_FILE = "[REDACTED: secret file]"

_ZERO_WIDTH = re.compile("[­​-‏⁠-⁤﻿]")

_PEM = re.compile(
    r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----.*?(?:-----END \1-----|\Z)", re.S
)

_KNOWN = [
    ("aws-access-key", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b"),
    ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    ("github-token", r"\bgithub_pat_[A-Za-z0-9_]{22,}"),
    ("anthropic-key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    ("openai-key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}"),
    ("slack-token", r"\bxox[abposre]-[A-Za-z0-9\-]{10,}"),
    ("slack-webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]+"),
    ("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}"),
    ("stripe-key", r"\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}"),
    ("stripe-webhook-secret", r"\bwhsec_[0-9A-Za-z]{16,}"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    ("npm-token", r"\bnpm_[A-Za-z0-9]{36}"),
    ("pypi-token", r"\bpypi-AgE[A-Za-z0-9_\-]{50,}"),
    ("huggingface-token", r"\bhf_[A-Za-z0-9]{30,}"),
    ("gitlab-token", r"\bglpat-[A-Za-z0-9_\-]{20,}"),
    ("sendgrid-key", r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"),
    ("digitalocean-token", r"\bdo[por]_v1_[a-f0-9]{64}"),
]
_KNOWN_RE = [(name, re.compile(p)) for name, p in _KNOWN]

_URL_CREDS = re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://)([^/\s:@'\"]+):([^/\s@'\"]+)@")
_AUTH_HEADER = re.compile(
    r"(?i)\b(authorization|proxy-authorization|x-api-key|api-key|x-auth-token|x-access-token|cookie|set-cookie)"
    r"(\s*:\s*)([^\r\n'\"]+)"
)
_BEARER = re.compile(r"(?i)\b(bearer|basic|token)(\s+)([A-Za-z0-9._~+/=\-]{8,})")
_CURL_USER = re.compile(r"((?:^|\s)(?:-u\s*|--user[=\s]+))(['\"]?)([^\s:'\"]+):([^\s'\"]+)")
_MYSQL_P = re.compile(r"(\s-p)(?!\s)(\S+)")
_SECRET_FLAG = re.compile(
    r"(?i)(--?(?:password|passwd|pass|token|secret|api[-_]?key|auth[-_]?token|access[-_]?token|"
    r"client[-_]?secret|private[-_]?key)(?:=|\s+))(['\"]?)([^\s'\"]+)"
)
_ASSIGN = re.compile(
    r"(?<![\w.\-/])([\"']?)([A-Za-z_][\w.\-]*)\1(\s*[:=]\s*)(?:([\"'])(.*?)\4|([^\s\"',;&)}\]]+))"
)
_ENTROPY_CAND = re.compile(r"[A-Za-z0-9+/=_\-]{32,}")
_HEX = re.compile(r"[0-9a-fA-F\-]+")

_KEY_SUBSTR = (
    "password", "passwd", "passphrase", "secret", "apikey", "api_key", "api-key", "accesskey",
    "access_key", "privatekey", "private_key", "credential", "authorization", "auth_token",
    "authtoken", "x-api-key",
)
_KEY_SEGMENTS = {"pass", "pwd", "token", "auth", "cookie", "signature", "sig", "pat", "dsn"}
_SEG_SPLIT = re.compile(r"[_\-.\s]+|(?<=[a-z0-9])(?=[A-Z])")
_SKIP_VALUES = {"true", "false", "null", "none", "nil", "undefined", "''", '""', ""}


def is_secret_key(key: str) -> bool:
    lower = key.lower()
    if any(s in lower for s in _KEY_SUBSTR):
        return True
    segments = {s.lower() for s in _SEG_SPLIT.split(key) if s}
    if "pwd" in segments and lower == "pwd":
        return False  # $PWD is the working directory, not a password
    return bool(segments & _KEY_SEGMENTS)


def _entropy(s: str) -> float:
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _looks_random(tok: str) -> bool:
    if "REDACTED" in tok or _HEX.fullmatch(tok):
        return False
    if tok.startswith(("/", "./", "~/", "-")):
        return False
    slashes = tok.count("/")
    if slashes >= 3 and (len(tok) - slashes) / (slashes + 1) < 16:
        return False  # path-like
    if not (re.search(r"[a-z]", tok) and re.search(r"[A-Z]", tok) and re.search(r"[0-9]", tok)):
        return False
    return _entropy(tok) >= 4.2


def _sub_assign(m: re.Match) -> str:
    key = m.group(2)
    value = m.group(5) if m.group(4) else m.group(6)
    if not is_secret_key(key) or value is None:
        return m.group(0)
    v = value.strip()
    if v.lower() in _SKIP_VALUES or v.startswith(("[REDACTED", "$", "{{", "<")) or "(" in v:
        return m.group(0)
    if m.group(4):
        q = m.group(4)
        return f"{m.group(1)}{key}{m.group(1)}{m.group(3)}{q}{REDACTED}{q}"
    return f"{m.group(1)}{key}{m.group(1)}{m.group(3)}{REDACTED}"


def _core(s: str) -> str:
    s = _PEM.sub(lambda m: f"-----BEGIN {m.group(1)}-----{REDACTED}-----END {m.group(1)}-----", s)
    for name, rx in _KNOWN_RE:
        s = rx.sub(f"[REDACTED:{name}]", s)
    s = _URL_CREDS.sub(lambda m: f"{m.group(1)}{m.group(2)}:{REDACTED}@", s)
    s = _AUTH_HEADER.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", s)
    s = _BEARER.sub(
        lambda m: m.group(0) if "REDACTED" in m.group(3) else f"{m.group(1)}{m.group(2)}{REDACTED}", s
    )
    s = _CURL_USER.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}:{REDACTED}", s)
    if "mysql" in s:
        s = _MYSQL_P.sub(lambda m: f"{m.group(1)}{REDACTED}", s)
    s = _SECRET_FLAG.sub(
        lambda m: m.group(0) if m.group(3).startswith("[REDACTED") else f"{m.group(1)}{m.group(2)}{REDACTED}", s
    )
    s = _ASSIGN.sub(_sub_assign, s)
    s = _ENTROPY_CAND.sub(lambda m: "[REDACTED:high-entropy]" if _looks_random(m.group(0)) else m.group(0), s)
    return s


def redact_str(s: str) -> str:
    if not s:
        return s
    if not s.isascii():
        s = unicodedata.normalize("NFKC", _ZERO_WIDTH.sub("", s))
    if "%" in s:
        from urllib.parse import unquote

        decoded = unquote(s)
        if decoded != s:
            red = _core(decoded)
            if red != decoded:
                s = red
    return _core(s)


def redact(obj):
    """Recursively redact strings (and dict keys) inside any JSON-like value."""
    if isinstance(obj, str):
        return redact_str(obj)
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            rk = redact_str(k) if isinstance(k, str) else k
            if isinstance(k, str) and is_secret_key(k) and isinstance(v, (str, int, float)) and not isinstance(v, bool):
                out[rk] = REDACTED if v not in ("", None) else v
            else:
                out[rk] = redact(v)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    return obj


_SECRET_NAMES = {
    ".env", "credentials", ".netrc", ".npmrc", ".pypirc", ".pgpass", ".git-credentials",
    ".dockercfg", "secrets.yml", "secrets.yaml", "secrets.json", ".htpasswd",
}
_SECRET_EXT = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".env", ".asc", ".gpg", ".tfvars")
_SECRET_PREFIX = (".env.", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
_SECRET_DIRS = ("/.aws/", "/.ssh/", "/.gnupg/", "/.docker/config.json", "/.kube/config")


def is_secret_path(path: str) -> bool:
    p = path.replace("\\", "/")
    base = p.rsplit("/", 1)[-1].lower()
    if base.endswith(".pub"):
        return False
    if base in _SECRET_NAMES or base.endswith(_SECRET_EXT) or base.startswith(_SECRET_PREFIX):
        return True
    if any(d in p for d in ("/.docker/config.json", "/.kube/config")):
        return True
    return "/.aws/" in p and base in ("credentials", "config")


_FILE_PATH_KEYS = ("file_path", "notebook_path", "path")
_CONTENT_KEYS = ("content", "old_string", "new_string", "edits", "new_source", "old_source")


def redact_event_payload(payload: dict) -> dict:
    """Redact a hook payload; drop file contents entirely for secret files."""
    payload = dict(payload)
    ti = payload.get("tool_input")
    if isinstance(ti, dict):
        fp = next((ti[k] for k in _FILE_PATH_KEYS if isinstance(ti.get(k), str)), None)
        if fp and is_secret_path(fp):
            ti = {k: (SECRET_FILE if k in _CONTENT_KEYS else v) for k, v in ti.items()}
            payload["tool_input"] = ti
            if "tool_response" in payload:
                payload["tool_response"] = SECRET_FILE
    return redact(payload)
