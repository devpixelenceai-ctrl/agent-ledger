"""`agent-ledger policy test | lint | trust | show`."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from agent_ledger.config import ledger_home
from agent_ledger.policy import (
    COMMAND_LEVEL_CHECKS, Context, Explanation, PolicyError, evaluate, load_policy, parse_policy,
)
from agent_ledger.policyfile import REPO_POLICY, trust_policy

_SUBJECT_KEY = {"Read": "file_path", "Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path",
                "NotebookEdit": "notebook_path", "WebFetch": "url", "Glob": "pattern", "Grep": "pattern",
                "WebSearch": "query"}


def run(args) -> int:
    return {"test": _test, "lint": _lint, "trust": _trust, "show": _show}[args.pcmd](args)


def _project(args) -> str:
    return str(Path(getattr(args, "project", None) or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()).resolve())


def _test(args) -> int:
    project = _project(args)
    home = ledger_home(os.environ)
    if args.policy:
        try:
            pol = parse_policy(Path(args.policy).read_text("utf-8"), args.policy)
        except (OSError, PolicyError) as e:
            print(f"cannot load {args.policy}: {e}", file=sys.stderr)
            return 1
    else:
        pol = load_policy(project, home)
    if args.input:
        tool_input = json.loads(args.input)
    elif args.tool == "Bash":
        tool_input = {"command": args.subject}
    else:
        tool_input = {_SUBJECT_KEY.get(args.tool, "file_path"): args.subject}
        if args.tool in ("Write", "Edit") and "file_path" in tool_input:
            tool_input.setdefault("content", "")
    raw = {}
    if args.tool.startswith("mcp__"):
        raw["mcp_server"] = {"name": args.tool.split("__")[1], "source": "user"}
    ctx = Context(project, cwd=args.cwd or project, settings=pol.settings, ledger_home=str(home))
    ex = Explanation()
    d = evaluate(pol, args.tool, tool_input, ctx, raw=raw, explain=ex)
    print(f"Policy:   {pol.source}  ({pol.hash[:20]}…)")
    for w in pol.warnings:
        print(f"Warning:  {w}")
    print(f"Project:  {project}")
    print("Units:")
    for level, label, rule_id, dec in ex.units:
        tag = "pipeline" if level == "command" else ("segment" if level == "segment" else "tool")
        print(f"  {tag:<9} {label[:70]:<70}  -> {dec:<5} [{rule_id or 'no rule'}]")
    print(f"Decision: {d.decision.upper()}  (rule {d.rule_id}, severity {d.severity})")
    print(f"Reason:   {d.reason}")
    return 0


def _lint(args) -> int:
    project = _project(args)
    if args.file:
        path = Path(args.file)
    else:
        repo = Path(project) / REPO_POLICY
        user = ledger_home(os.environ) / "policy.toml"
        path = repo if repo.exists() else user if user.exists() else None
        if path is None:
            print("No policy file found (the built-in starter policy is in force).")
            return 0
    try:
        pol = parse_policy(path.read_text("utf-8"), str(path))
    except (OSError, UnicodeDecodeError, PolicyError) as e:
        print(f"ERROR: {e}")
        return 1
    warnings = []
    seen_deny = False
    for i, r in enumerate(pol.rules):
        catch_all = not any([r.tools, r.commands, r.command, r.paths, r.domains, r.checks, r.mcp_source,
                             r.within_project is not None])
        if catch_all and i < len(pol.rules) - 1:
            warnings.append(f"rule {r.id!r} matches everything, so the {len(pol.rules) - i - 1} rule(s) after it never apply")
        if r.decision == "deny":
            if any(p.decision == "allow" and not p.checks and p.within_project is None for p in pol.rules[:i]) and not seen_deny:
                warnings.append(f"deny rule {r.id!r} comes after a broad allow rule; first match wins, so it may never fire")
            seen_deny = True
        if set(r.checks) & COMMAND_LEVEL_CHECKS and r.tools and "Bash" not in r.tools:
            warnings.append(f"rule {r.id!r} uses a shell pipeline check but does not apply to Bash")
    for w in warnings:
        print(f"WARNING: {w}")
    print(f"OK: {path} ({len(pol.rules)} rules, default {pol.default_decision})")
    return 0


def _trust(args) -> int:
    path = Path(args.file or REPO_POLICY)
    if not path.exists():
        print(f"{path} not found", file=sys.stderr)
        return 1
    try:
        parse_policy(path.read_text("utf-8"), str(path))
    except (OSError, UnicodeDecodeError, PolicyError) as e:
        print(f"Refusing to trust an invalid policy: {e}", file=sys.stderr)
        return 1
    digest = trust_policy(path, ledger_home(os.environ))
    print(f"Trusted {path.resolve()} (sha256 {digest})")
    return 0


def _show(args) -> int:
    project = _project(args)
    pol = load_policy(project, ledger_home(os.environ))
    print(f"Policy in force: {pol.source}")
    print(f"Hash:            {pol.hash}")
    print(f"Rules:           {len(pol.rules)} (default decision: {pol.default_decision})")
    for w in pol.warnings:
        print(f"Warning:         {w}")
    return 0
