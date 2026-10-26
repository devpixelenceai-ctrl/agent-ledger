# Contributing

Thanks for helping. agent-ledger is small on purpose: the Python standard library only, a hook that must stay fast, and a policy engine that must stay hard to fool.

## Set up

```bash
python3.11 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
```

The latency benchmark asserts a p95 under 50 ms. On a busy machine, Python start-up alone can exceed that, so if it fails, the output shows the bare-interpreter baseline. You can run with `AGENT_LEDGER_BENCH_ENFORCE=0` to report latency without failing.

## Ground rules

- **No runtime dependencies.** Only the standard library at runtime. pytest is fine for development.
- **Keep the hot path lean.** `agent-ledger hook` runs before every tool call. `tests/test_benchmark.py::test_hot_path_imports_stay_lean` fails if a heavy import creeps into it. Import anything else lazily.
- **Test first.** Write the failing test, then the fix.
- **Policy and parser changes need adversarial tests.**
  - When you add or loosen a rule, add cases to `tests/test_bypass.py` showing what is now allowed and what must still be blocked. See `test_trial_allowances_stay_narrow` for the pattern.
  - When you fix a bypass, add the exact bypass as a regression test, and add a row to `docs/red-team.md`.
- **Never log secret values.** Anything that reaches the ledger goes through `redact.py`. Decision reasons may name files and kinds of secret, never values.
- **Don't run programs from untrusted repos.** Code that reads a project, such as the git secret scan, must not trigger that repo's git config (fsmonitor, filters, diff drivers).

## Adding an agent

An adapter maps the agent's native events onto the canonical model in `agent_ledger/adapters/` (see `opencode.py`). The policy, redaction, ledger and reports are shared. Add an `init --agent <name>` path, and re-run the bypass suites through your adapter, as `tests/test_opencode.py` does.

## Pull requests

- Keep changes focused.
- Explain the threat or the bug.
- Make sure `pytest` passes and `agent-ledger policy lint agent_ledger/policies/starter.toml` is clean.

For security issues, follow [SECURITY.md](SECURITY.md) instead of opening a public PR.
