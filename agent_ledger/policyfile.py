"""Policy file selection and trust pinning. Kept import-light: every hook event uses it."""

from __future__ import annotations

import json
import os
from pathlib import Path

STARTER = Path(__file__).with_name("policies") / "starter.toml"
REPO_POLICY = ".agent-ledger.toml"

try:
    from _sha2 import sha256 as _sha256_ctor  # Python 3.12+
except ImportError:  # pragma: no cover
    try:
        from _sha256 import sha256 as _sha256_ctor  # Python 3.11
    except ImportError:
        from hashlib import sha256 as _sha256_ctor


def sha256(data: bytes) -> str:
    return _sha256_ctor(data).hexdigest()


def trust_file(home: Path) -> Path:
    return Path(home) / "trusted.json"


def _read_trust(home: Path) -> dict:
    try:
        data = json.loads(trust_file(home).read_text("utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def is_trusted(path: Path, digest: str, home: Path) -> bool:
    return _read_trust(home).get(str(Path(path).resolve())) == digest


def trust_policy(path: Path, home: Path) -> str:
    """Pin the current contents of a repo policy file as trusted. Returns its hash."""
    path = Path(path).resolve()
    digest = sha256(path.read_bytes())
    data = _read_trust(home)
    data[str(path)] = digest
    home = Path(home)
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    tf = trust_file(home)
    tmp = tf.with_name(tf.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, tf)
    return digest


def policy_ref(project_dir: str | None, home: Path) -> str:
    """Hash of the policy file that load_policy would select, without parsing it."""
    try:
        if project_dir:
            repo = Path(project_dir) / REPO_POLICY
            if repo.is_file():
                digest = sha256(repo.read_bytes())
                if is_trusted(repo, digest, home):
                    return digest
        user = Path(home) / "policy.toml"
        if user.is_file():
            return sha256(user.read_bytes())
        return "builtin:" + sha256(STARTER.read_bytes())
    except OSError:
        return "unknown"
