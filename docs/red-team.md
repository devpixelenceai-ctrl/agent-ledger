# Red-team log

Every finding becomes a regression test in `tests/test_redteam.py`, `tests/test_bypass.py`
or `tests/test_redact.py`. Read this together with `docs/threat-model.md`.

## Pass 1 (after M2)

| # | Finding | Severity | Fix |
|---|---|---|---|
| 1 | Brace expansion was exponential: `echo {a,b}{a,b}…` (40 groups) hung the parser. A hook that times out **fails open**, so the command ran unchecked. | high | Breadth-first expansion capped at 64 words. When the cap is hit, the command is marked unparseable, so the policy asks. |
| 2 | Glob expansion walked the filesystem (`cat /*/*/*/*/*/.env`), which risked a timeout and fail-open. It also matched dotfiles for `*`, which bash does not. | medium | Globs expand within one directory only, capped at 500 results, with no hidden files unless the pattern names them. A wildcard in a directory part is checked against a list of sensitive file names instead. |
| 3 | The SQLite lock wait (10 s) equalled the hook timeout. A held lock could make Claude Code kill the hook, which loses a deny. | medium | The hook waits at most 3 s for the lock. |
| 4 | `.git/HEAD`, refs and `config.toml` were read without a regular-file check. A FIFO would hang the read. | low | Only regular files are read, at most 4 KB each. |
| 5 | A NUL byte in a path raised `ValueError` in `realpath`, which crashed policy evaluation (fail-open). | medium | Paths that cannot be resolved are classified as unknown. Parser fuzz cases were added. |
| 6 | The `-wal` and `-shm` files could be created with the default umask (readable by others). | low | `connect()` and `append()` run under umask 077. A test checks the file modes. |
| 7 | A secret split by shell quotes (`sk-ant-""api03…`) evaded the token patterns. | medium | The quote-joined form of each command is redacted too. If it hides a secret, the redacted joined form is stored instead. |
| 8 | Hex-encoded secrets (`xxd -p`) passed through, because hex was exempt from the entropy check so that SHAs survive. | medium | Hex runs longer than 64 characters (longer than a SHA-256) are redacted. |
| 9 | Deleting the newest rows (tail truncation) left a valid chain. | medium | `verify` cross-checks the per-session tool-call counters, which are kept separately. `verify --expect-head <hash>` checks against an anchored head. |
| 10 | Text that only *mentions* a secret file (`git commit -m "ignore .env"`, `grep .env src`) was treated as reading it. This was a false positive, found by dogfooding. | low (usability) | echo/printf text, commit messages, and grep/sed/awk/jq patterns are treated as data. Real file operands are still checked. |

**Still open by design** (documented in the threat model):
- Full-chain rewrites by someone who can write the database. The mitigations are an HMAC key the agent cannot read, and head anchoring.
- Secrets in encodings the redactor does not know, such as ROT13 or short base64 pieces.
- Commands whose behaviour depends on files the agent wrote earlier.
