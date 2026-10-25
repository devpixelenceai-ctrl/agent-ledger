"""agent-ledger command line. `hook` takes a fast path that skips argparse and other imports."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["hook"]:
        from agent_ledger.hook import main as hook_main

        return hook_main()
    return _main_slow(argv)


def _build_parser():
    import argparse

    p = argparse.ArgumentParser(prog="agent-ledger", description="Flight recorder and policy gate for AI coding agents.")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("hook", help="hook entry point (run by Claude Code; reads JSON on stdin)")

    i = sub.add_parser("init", help="install hooks into .claude/settings.json and copy the starter policy")
    i.add_argument("--project", help="project directory (default: current directory)")
    i.add_argument("--user", action="store_true", help="install into ~/.claude/settings.json instead")
    i.add_argument("--command", help='hook command to write (default: "agent-ledger hook")')
    i.add_argument("--absolute", action="store_true", help="write this interpreter's absolute path as the command")
    i.add_argument("--fail-closed", action="store_true", help="block tool calls when agent-ledger itself fails")

    v = sub.add_parser("verify", help="verify the hash chain")
    v.add_argument("--db", help="ledger database (default: from config)")
    return p


def _main_slow(argv: list[str]) -> int:
    args = _build_parser().parse_args(argv)
    if args.cmd == "init":
        return _cmd_init(args)
    if args.cmd == "verify":
        return _cmd_verify(args)
    return 2


def _cmd_init(args) -> int:
    import os
    import shlex
    from pathlib import Path

    from agent_ledger.config import ledger_home
    from agent_ledger.init import InitError, install_hooks

    project = Path(args.project or os.getcwd()).resolve()
    settings = Path.home() / ".claude" / "settings.json" if args.user else project / ".claude" / "settings.json"
    if args.command:
        command = args.command
    elif args.absolute:
        command = f"{shlex.quote(sys.executable)} -m agent_ledger hook"
    else:
        command = "agent-ledger hook"
    try:
        changed = install_hooks(settings, command, fail_closed=args.fail_closed)
    except InitError as e:
        print(f"agent-ledger init: {e}", file=sys.stderr)
        return 1
    print(f"{'Updated' if changed else 'Already up to date:'} {settings}")
    if args.fail_closed:
        home = ledger_home(os.environ)
        cfg = home / "config.toml"
        if cfg.exists():
            print(f'Set fail_mode = "closed" under [ledger] in {cfg} to finish enabling fail-closed mode.')
        else:
            home.mkdir(parents=True, exist_ok=True, mode=0o700)
            cfg.write_text('[ledger]\nfail_mode = "closed"\n', "utf-8")
            print(f"Wrote {cfg} (fail_mode = closed)")
    print("Next: start (or continue) a Claude Code session; events land in the ledger. Check with: agent-ledger verify")
    return 0


def _cmd_verify(args) -> int:
    import os
    from pathlib import Path

    from agent_ledger import store
    from agent_ledger.config import load_config

    cfg = load_config(os.environ)
    db = Path(args.db) if args.db else cfg.db_path
    if not db.exists():
        print(f"No ledger at {db} yet.")
        return 0
    r = store.verify(store.connect(db, readonly=True), key=cfg.hmac_key)
    if r.ok:
        print(f"OK: {r.checked} events, chain intact.\nHead hash: {r.head_hash}")
        return 0
    print(f"BROKEN at seq {r.first_bad_seq}: {r.reason}\nVerified {r.checked} events before the break.")
    print(f"Last good hash: {r.head_hash}")
    return 1
