"""Runtime configuration.

Ledger settings are per-user, never per-repo: a cloned repository must not be able to
redirect the log or weaken the fail mode. Sources, later wins:
  defaults -> ~/.agent-ledger/config.toml [ledger] -> environment variables.
"""

from __future__ import annotations

import os
from pathlib import Path

FAIL_MODES = ("open", "closed")


class Config:
    __slots__ = ("home", "db_path", "fail_mode", "max_field_chars", "hmac_key", "warnings")

    def __init__(self, home: Path, db_path: Path, fail_mode: str = "open", max_field_chars: int = 65536,
                 hmac_key: bytes | None = None, warnings: tuple = ()):
        self.home, self.db_path, self.fail_mode = home, db_path, fail_mode
        self.max_field_chars, self.hmac_key, self.warnings = max_field_chars, hmac_key, warnings

    @property
    def fail_closed(self) -> bool:
        return self.fail_mode == "closed"


def ledger_home(env) -> Path:
    return Path(env.get("AGENT_LEDGER_HOME") or Path.home() / ".agent-ledger").expanduser()


def load_config(env=None) -> Config:
    env = os.environ if env is None else env
    home = ledger_home(env)
    warnings: list[str] = []
    section: dict = {}
    cfg_file = home / "config.toml"
    if cfg_file.exists():
        import tomllib

        try:
            section = tomllib.loads(cfg_file.read_text("utf-8")).get("ledger", {})
        except (OSError, ValueError) as e:  # TOMLDecodeError and UnicodeDecodeError are ValueErrors
            warnings.append(f"invalid {cfg_file}: {e}; using defaults")

    fail_mode = str(env.get("AGENT_LEDGER_FAIL_MODE") or section.get("fail_mode", "open"))
    if fail_mode not in FAIL_MODES:
        warnings.append(f"unknown fail_mode {fail_mode!r}; using 'open'")
        fail_mode = "open"

    db_path = Path(env.get("AGENT_LEDGER_DB") or section.get("db_path") or home / "ledger.db").expanduser()

    try:
        max_chars = int(section.get("max_field_chars", 65536))
    except (TypeError, ValueError):
        max_chars = 65536

    key: bytes | None = None
    if env.get("AGENT_LEDGER_HMAC_KEY"):
        key = env["AGENT_LEDGER_HMAC_KEY"].encode()
    elif section.get("hmac_key_file"):
        try:
            key = Path(section["hmac_key_file"]).expanduser().read_bytes().strip() or None
        except OSError as e:
            warnings.append(f"cannot read hmac_key_file: {e}")

    return Config(home, db_path, fail_mode, max_chars, key, tuple(warnings))
