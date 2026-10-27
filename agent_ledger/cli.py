"""agent-ledger command line. `hook` takes a fast path that skips argparse and other imports."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["hook"]:
        from agent_ledger.hook import main as hook_main

        opts = {"--agent": "claude-code", "--event": None}
        rest = argv[1:]
        while rest:
            key, _, value = rest[0].partition("=")
            if key in opts and value:
                opts[key], rest = value, rest[1:]
            elif key in opts and len(rest) > 1:
                opts[key], rest = rest[1], rest[2:]
            else:
                rest = rest[1:]
        return hook_main(agent=opts["--agent"], event=opts["--event"])
    if argv[:1] == ["git-hook"]:
        from agent_ledger.githook import main as githook_main

        return githook_main(argv[1:])
    return _main_slow(argv)


def _build_parser():
    import argparse

    p = argparse.ArgumentParser(prog="agent-ledger", description="Flight recorder and policy gate for AI coding agents.")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("hook", help="hook entry point (run by Claude Code; reads JSON on stdin)")
    sub.add_parser("git-hook", help="git pre-commit / pre-push entry point (installed by init --agent git)")

    i = sub.add_parser("init", help="install agent-ledger into a project (Claude Code hooks or an OpenCode plugin)")
    from agent_ledger.agent_configs import CONFIGS

    i.add_argument("--agent", choices=["claude-code", "opencode", "kilo", "amp", "git", *sorted(CONFIGS)], default="claude-code",
                   help="which agent to govern (default: claude-code)")
    i.add_argument("--project", help="project directory (default: current directory)")
    i.add_argument("--user", action="store_true", help="install into ~/.claude/settings.json instead")
    i.add_argument("--command", help='hook command to write (default: "agent-ledger hook")')
    i.add_argument("--absolute", action="store_true", help="write this interpreter's absolute path as the command")
    i.add_argument("--fail-closed", action="store_true", help="block tool calls when agent-ledger itself fails")
    i.add_argument("--no-policy", action="store_true", help="do not copy the starter policy")

    v = sub.add_parser("verify", help="verify the hash chain")
    v.add_argument("--db", help="ledger database (default: from config)")
    v.add_argument("--expect-head", help="a head hash recorded earlier; fail if it is no longer in the chain")

    ss = sub.add_parser("sessions", help="list recorded sessions")
    ss.add_argument("--since", help="YYYY-MM-DD, ISO timestamp, or 7d / 12h")
    ss.add_argument("--limit", type=int, default=50)
    sw = sub.add_parser("show", help="timeline of one session")
    sw.add_argument("session", help="session id or unique prefix")
    sw.add_argument("--decision", choices=["allow", "ask", "deny", "error"], help="only show this decision")
    tl = sub.add_parser("tail", help="latest events")
    tl.add_argument("-n", type=int, default=20, help="number of events (default 20)")
    tl.add_argument("-f", "--follow", action="store_true", help="keep printing new events")
    rp = sub.add_parser("report", help="write an audit report")
    scope = rp.add_mutually_exclusive_group()
    scope.add_argument("--session", help="session id or unique prefix")
    scope.add_argument("--since", help="YYYY-MM-DD, ISO timestamp, or 7d / 12h")
    rp.add_argument("--format", choices=["md", "html", "json"], default="md")
    rp.add_argument("-o", "--output", help="output file (default: stdout)")
    sv = sub.add_parser("serve", help="start the read-only dashboard on 127.0.0.1")
    sv.add_argument("--port", type=int, default=8765)
    sv.add_argument("--open", action="store_true", help="open it in the default browser")
    sv.add_argument("--demo", action="store_true", help="serve a throwaway demo ledger instead of yours")
    for p_ in (ss, sw, tl, rp, sv):
        p_.add_argument("--db", help="ledger database (default: from config)")

    pol = sub.add_parser("policy", help="inspect, test and trust policies")
    psub = pol.add_subparsers(dest="pcmd", required=True)
    t = psub.add_parser("test", help="show which rule decides a command or tool call")
    t.add_argument("subject", help="shell command, or the file path / URL for --tool")
    t.add_argument("--tool", default="Bash", help="tool name (default: Bash)")
    t.add_argument("--input", help="full tool_input as JSON (overrides subject)")
    t.add_argument("--project", help="project directory (default: current directory)")
    t.add_argument("--cwd", help="working directory (default: project)")
    t.add_argument("--policy", help="policy file to use instead of the one in force")
    lint = psub.add_parser("lint", help="validate a policy file")
    lint.add_argument("file", nargs="?", help="policy file (default: the one in force)")
    lint.add_argument("--project", help="project directory (default: current directory)")
    tr = psub.add_parser("trust", help="pin the repo policy so the hook will use it")
    tr.add_argument("file", nargs="?", help="policy file (default: ./.agent-ledger.toml)")
    sh = psub.add_parser("show", help="show which policy is in force and why")
    sh.add_argument("--project", help="project directory (default: current directory)")
    return p


def _main_slow(argv: list[str]) -> int:
    args = _build_parser().parse_args(argv)
    if args.cmd == "init":
        return _cmd_init(args)
    if args.cmd == "verify":
        return _cmd_verify(args)
    if args.cmd in ("sessions", "show", "tail", "report"):
        from agent_ledger import browse

        return getattr(browse, f"cmd_{args.cmd}")(args)
    if args.cmd == "serve":
        import os

        from agent_ledger.config import load_config
        from agent_ledger.server import serve

        cfg = load_config(os.environ)
        if args.demo:
            from agent_ledger.demo import build_demo

            db = build_demo()
            print(f"Demo ledger: {db}")
            return serve(db, port=args.port, open_browser=args.open)
        return serve(args.db or cfg.db_path, port=args.port, hmac_key=cfg.hmac_key, open_browser=args.open)
    if args.cmd == "policy":
        from agent_ledger import policy_cli

        return policy_cli.run(args)
    return 2


def _absolute_hook_command() -> str:
    import os
    import shlex

    script = os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0] else ""
    if os.path.basename(script) == "agent-ledger" and os.access(script, os.X_OK):
        return f"{shlex.quote(script)} hook"  # the console script (e.g. ~/.local/bin/agent-ledger)
    return f"{shlex.quote(sys.executable)} -m agent_ledger hook"


def _hook_argv(agent: str) -> list[str]:
    """The exact installation running `init`, as an argv list (used by the OpenCode plugin)."""
    import os

    script = os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0] else ""
    if os.path.basename(script) == "agent-ledger" and os.access(script, os.X_OK):
        return [script, "hook", "--agent", agent]
    return [sys.executable, "-m", "agent_ledger", "hook", "--agent", agent]


def _cmd_init(args) -> int:
    import os
    from pathlib import Path

    from agent_ledger.config import ledger_home
    from agent_ledger.init import InitError

    project = Path(args.project or os.getcwd()).resolve()
    if args.agent in ("opencode", "kilo", "amp"):
        from agent_ledger.init import install_amp_plugin, install_opencode_plugin

        argv = _hook_argv(args.agent)
        rel = {"opencode": ".opencode/plugins/agent-ledger.js", "kilo": ".kilo/plugins/agent-ledger.js",
               "amp": ".amp/plugins/agent-ledger.ts"}[args.agent]
        try:
            if args.agent == "amp":
                changed = install_amp_plugin(project, argv, fail_closed=args.fail_closed)
            else:
                changed = install_opencode_plugin(project, argv, fail_closed=args.fail_closed, dest=os.path.dirname(rel))
        except InitError as e:
            print(f"agent-ledger init: {e}", file=sys.stderr)
            return 1
        plugin = project / rel
        print(f"{'Installed' if changed else 'Already up to date:'} {plugin}")
        print(f"  hook: {' '.join(argv)}")
    elif args.agent not in ("claude-code", "git"):
        from agent_ledger.agent_configs import CONFIGS, install_agent

        spec = CONFIGS[args.agent]
        try:
            changed = install_agent(args.agent, project, _hook_argv(args.agent)[:-2], fail_closed=args.fail_closed)
        except InitError as e:
            print(f"agent-ledger init: {e}", file=sys.stderr)
            return 1
        where = ", ".join(str(p.relative_to(project)) for p in spec.files(project))
        print(f"{'Installed' if changed else 'Already up to date:'} {args.agent} hooks in {where}")
        if spec.note:
            print(f"  {spec.note}")
    elif args.agent == "git":
        from agent_ledger.init import install_git_hooks

        cli = _hook_argv("git")[:-3]  # the agent-ledger command itself, without "hook --agent git"
        try:
            changed = install_git_hooks(project, cli)
        except InitError as e:
            print(f"agent-ledger init: {e}", file=sys.stderr)
            return 1
        print(f"{'Installed' if changed else 'Already up to date:'} git pre-commit and pre-push hooks")
        print("  Commits and pushes by any tool (including agents without hooks) now go through the policy.")
        print("  Aider skips git hooks by default: run it with --git-commit-verify.")
    elif _install_claude_hooks(args, project) != 0:
        return 1
    return _init_policy_and_config(args, project)


def _install_claude_hooks(args, project) -> int:
    import shutil
    from pathlib import Path

    from agent_ledger.init import InitError, install_hooks

    settings = Path.home() / ".claude" / "settings.json" if args.user else project / ".claude" / "settings.json"
    if args.command:
        command = args.command
    elif args.absolute:
        command = _absolute_hook_command()
    elif shutil.which("agent-ledger"):
        command = "agent-ledger hook"
    else:
        # A bare command that is not on PATH fails with "command not found", which Claude Code
        # treats as non-blocking: the session would silently run ungoverned.
        command = _absolute_hook_command()
        print("Note: `agent-ledger` is not on your PATH (try `pipx ensurepath`), so the hook uses the full path:")
        print(f"  {command}")
    try:
        changed = install_hooks(settings, command, fail_closed=args.fail_closed)
    except InitError as e:
        print(f"agent-ledger init: {e}", file=sys.stderr)
        return 1
    print(f"{'Updated' if changed else 'Already up to date:'} {settings}")
    return 0


def _init_policy_and_config(args, project) -> int:
    import os

    from agent_ledger.config import ledger_home

    if not args.no_policy:
        from agent_ledger.policyfile import REPO_POLICY, STARTER, trust_policy

        home = ledger_home(os.environ)
        target = (home / "policy.toml") if args.user else (project / REPO_POLICY)
        from agent_ledger.init import write_exclusive

        target.parent.mkdir(parents=True, exist_ok=True)
        if not write_exclusive(target, STARTER.read_text("utf-8")):
            # Never auto-trust a policy we did not write: it may have come with a cloned repo.
            kind = "symlink" if target.is_symlink() else "policy"
            print(f"Kept existing {kind} {target}")
            if not args.user:
                print(f"Review it, then run `agent-ledger policy trust {target}` so the hook will use it.")
        else:
            print(f"Wrote starter policy {target}")
            if not args.user:
                digest = trust_policy(target, home)
                print(f"Trusted {target.name} (sha256 {digest[:12]}). Re-run `agent-ledger policy trust` after editing it.")
    if args.fail_closed:
        home = ledger_home(os.environ)
        cfg = home / "config.toml"
        if cfg.exists():
            print(f'Set fail_mode = "closed" under [ledger] in {cfg} to finish enabling fail-closed mode.')
        else:
            home.mkdir(parents=True, exist_ok=True, mode=0o700)
            cfg.write_text('[ledger]\nfail_mode = "closed"\n', "utf-8")
            print(f"Wrote {cfg} (fail_mode = closed)")
    agent = {"opencode": "an OpenCode session (opencode / opencode run)", "claude-code": "a Claude Code session",
             "git": "committing"}.get(args.agent, f"a {args.agent} session")
    print(f"Next: start (or continue) {agent}; events land in the ledger. Check with: agent-ledger verify")
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
    r = store.verify(store.connect(db, readonly=True), key=cfg.hmac_key, expect_head=args.expect_head)
    if r.ok:
        print(f"OK: {r.checked} events, chain intact.\nHead hash: {r.head_hash}")
        return 0
    if r.first_bad_seq is None:
        print(f"BROKEN: {r.reason}\nThe {r.checked} events present are internally consistent.")
        return 1
    print(f"BROKEN at seq {r.first_bad_seq}: {r.reason}\nVerified {r.checked} events before the break.")
    print(f"Last good hash: {r.head_hash}")
    return 1
