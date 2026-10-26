"""Policy engine: TOML rules -> allow / ask / deny for a tool call.

Evaluation model (docs/policy-reference.md):
- A tool call becomes one or more *units*. Non-shell tools are one unit. A shell command
  becomes one unit per simple command (segment) plus one *command-level* unit for checks
  that need the whole pipeline (e.g. `curl ... | sh`).
- Each unit is matched against the rules in order; the first rule whose conditions all
  match decides that unit. A segment that matches no rule gets `default_decision`.
- The call's decision is the strictest unit decision: deny > ask > allow.
"""

from __future__ import annotations

import fnmatch
import glob as _glob
import os
import re
from pathlib import Path

from agent_ledger.model import Decision
from agent_ledger.policyfile import REPO_POLICY, STARTER, is_trusted, policy_ref, sha256 as _sha256, trust_policy  # noqa: F401
from agent_ledger.shellparse import FETCHERS, INTERPRETERS, SHELLS, Segment, parse as parse_shell

DECISIONS = ("allow", "ask", "deny")
RANK = {"allow": 1, "ask": 2, "deny": 3}
SEVERITIES = ("info", "low", "medium", "high", "critical")
DEFAULT_SEVERITY = {"allow": "info", "ask": "medium", "deny": "high"}

RULE_KEYS = {
    "id", "description", "decision", "severity", "reason", "tools", "commands", "command", "paths",
    "exclude_paths", "access", "within_project", "domains", "check", "mcp_source",
}
SETTINGS_KEYS = {"default_decision", "allowed_domains", "max_delete_files", "protected_branches", "temp_dirs"}
COMMAND_LEVEL_CHECKS = {"remote_pipe_to_shell", "pipe_to_shell", "unparseable"}
SEGMENT_CHECKS = {
    "delete_outside_project", "write_outside_project", "unknown_write_target", "too_many_deletes",
    "git_force_push_protected", "chmod_world_writable", "dynamic_command", "inline_code", "runs_script",
    "git_config_override",
}
DELETE_CMDS = {"rm", "rmdir", "unlink", "shred", "srm", "trash", "trash-put"}
SPECIAL_PATHS = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin", "/dev/tty", "/dev/zero",
                 "/dev/random", "/dev/urandom"}
DEFAULT_TEMP = ["/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/var/folders", "/private/var/folders"]
_URL = re.compile(r"\b(?:https?|ftps?|wss?)://[^\s'\"<>`)]+", re.I)
_SCPLIKE = re.compile(r"^(?:[\w.\-]+@)?([A-Za-z0-9.\-]+\.[A-Za-z]{2,}|localhost):")


class PolicyError(Exception):
    pass


# ---------------------------------------------------------------- context & paths

class Context:
    def __init__(self, project_dir: str | None, cwd: str | None = None, env=None, settings=None,
                 ledger_home: str | None = None, extra_temp: list[str] | None = None):
        env = os.environ if env is None else env
        self.env = env
        self.home = env.get("HOME") or os.path.expanduser("~")
        self.project = os.path.realpath(project_dir or cwd or os.getcwd())
        self.cwd = cwd or self.project
        self.ledger_home = os.path.realpath(ledger_home or env.get("AGENT_LEDGER_HOME") or os.path.join(self.home, ".agent-ledger"))
        settings = settings or {}
        temps = list(settings.get("temp_dirs", DEFAULT_TEMP)) + list(extra_temp or [])
        if env.get("TMPDIR"):
            temps.append(env["TMPDIR"])
        self.temp = [os.path.realpath(os.path.expanduser(t)) for t in temps if t]
        self.allowed_domains = [d.lower().lstrip(".") for d in settings.get("allowed_domains", [])]
        self.max_delete = int(settings.get("max_delete_files", 10))
        self.protected = list(settings.get("protected_branches", ["main", "master"]))


class PathRef:
    __slots__ = ("text", "resolved", "cls", "cwd")

    def __init__(self, text, resolved, cls, cwd):
        self.text, self.resolved, self.cls, self.cwd = text, resolved, cls, cwd

    def __repr__(self):
        return f"PathRef({self.text!r}->{self.resolved!r}:{self.cls})"


def _within(path: str, base: str) -> bool:
    return path == base or path.startswith(base.rstrip("/") + "/")


def classify(text: str, dynamic: bool, cwd: str | None, ctx: Context) -> PathRef:
    if dynamic or not text or "\x00" in text:
        return PathRef(text, None, "unknown", cwd)
    try:
        return _classify(text, cwd, ctx)
    except (OSError, ValueError, UnicodeError):
        return PathRef(text, None, "unknown", cwd)


def _classify(text: str, cwd: str | None, ctx: Context) -> PathRef:
    t = text.replace("\\", "/") if os.sep == "\\" else text
    if t in SPECIAL_PATHS or t.startswith("/dev/fd/"):
        return PathRef(text, t, "special", cwd)
    if t == "~" or t.startswith("~/"):
        t = ctx.home + t[1:]
    elif t.startswith("~"):
        t = os.path.expanduser(t)  # ~otheruser
    if not os.path.isabs(t):
        if cwd is None:
            return PathRef(text, None, "unknown", cwd)
        t = os.path.join(cwd, t)
    is_glob = any(c in t for c in "*?[")
    whole_dir_glob = False
    base = t
    if is_glob:
        head = t[: min(t.index(c) for c in "*?[" if c in t)]
        base = head.rsplit("/", 1)[0] or "/"
        rest = t[len(base):].lstrip("/")
        whole_dir_glob = "/" not in rest and rest in ("*", ".*", "*.*", ".[!.]*", "..?*")
    resolved = os.path.realpath(base)
    resolved_full = resolved.rstrip("/") + "/" + t[len(base):].lstrip("/") if is_glob else resolved
    if _within(resolved, ctx.project):
        if resolved == ctx.project and (not is_glob or whole_dir_glob):
            cls = "root"
        else:
            cls = "inside"
    elif any(_within(resolved, tdir) for tdir in ctx.temp):
        cls = "temp"
    else:
        cls = "outside"
    return PathRef(text, resolved_full, cls, cwd)


# ---------------------------------------------------------------- units

class Unit:
    __slots__ = ("tool", "level", "text", "segment", "parsed", "reads", "writes", "deletes", "hosts",
                 "flags", "mcp_source", "label")

    def __init__(self, tool, level, text, label=None):
        self.tool, self.level, self.text = tool, level, text
        self.label = label or text
        self.segment: Segment | None = None
        self.parsed = None
        self.reads: list[PathRef] = []
        self.writes: list[PathRef] = []
        self.deletes: list[PathRef] = []
        self.hosts: list[str] = []
        self.flags: set[str] = set()
        self.mcp_source: str | None = None

    def all_paths(self):
        return self.reads + self.writes + self.deletes


def _host(url: str) -> str | None:
    from urllib.parse import urlsplit

    try:
        h = urlsplit(url if "://" in url else "http://" + url).hostname
    except ValueError:
        return None
    return h.rstrip(".").lower() if h else None


def _hosts_in(text: str) -> list[str]:
    return [h for h in (_host(u) for u in _URL.findall(text)) if h]


def _operands(args, dyn):
    out, end_opts = [], False
    for a, d in zip(args, dyn):
        if not end_opts and a == "--":
            end_opts = True
            continue
        if not end_opts and a.startswith("-") and a != "-":
            continue
        out.append((a, d))
    return out


def _opt_values(args, dyn, names):
    vals = []
    for i, a in enumerate(args):
        for n in names:
            if a == n and i + 1 < len(args):
                vals.append((args[i + 1], dyn[i + 1]))
            elif n.startswith("--") and a.startswith(n + "="):
                vals.append((a[len(n) + 1:], dyn[i]))
            elif not n.startswith("--") and a.startswith(n) and len(a) > len(n) and len(n) == 2:
                vals.append((a[2:], dyn[i]))
    return vals


_MSG_OPTS = {"-m", "--message", "-S", "-G", "--grep", "--author", "--committer", "-F"}
_PATTERN_CMDS = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "jq", "yq", "awk", "gawk", "mawk", "nawk", "sed", "gsed"}


def _data_positions(cmd: str, args: list[str]) -> set[int]:
    """Indices of arguments that are text, not file names (echo text, commit messages, patterns).

    Everything else is treated as a potential path, so `cat .env` is caught, while
    `git commit -m "ignore .env"` or `grep .env src/` are not mistaken for reading .env.
    """
    if cmd in ("echo", "printf"):
        return set(range(len(args)))
    data: set[int] = set()
    sub = args[0] if args else ""
    if cmd == "git" or cmd in _PATTERN_CMDS:
        for i, a in enumerate(args):
            if a in _MSG_OPTS and cmd == "git" and a != "-F" and i + 1 < len(args):
                data.add(i + 1)
            elif cmd == "git" and (a.startswith(("--message=", "--grep=", "--author=")) or (a.startswith("-m") and len(a) > 2)):
                data.add(i)
            elif cmd in _PATTERN_CMDS and a in ("-e", "--regexp", "--expression") and i + 1 < len(args):
                data.add(i + 1)
    if cmd in _PATTERN_CMDS or (cmd == "git" and sub == "grep"):
        start = 1 if cmd == "git" else 0
        uses_e = any(a in ("-e", "--regexp", "--expression", "-f", "--file") for a in args)
        if not uses_e:
            end_opts = False
            for i in range(start, len(args)):
                a = args[i]
                if a == "--" and not end_opts:
                    end_opts = True
                    continue
                if not end_opts and a.startswith("-") and a != "-":
                    continue
                data.add(i)  # first operand: the pattern / program / filter
                break
    if cmd == "agent-ledger" and args[:2] == ["policy", "test"] and len(args) > 2:
        data.add(2)
    return data


def analyze_segment(seg: Segment, ctx: Context) -> Unit:
    u = Unit("Bash", "segment", seg.text)
    u.segment = seg
    cmd, args, dyn = seg.cmd, seg.argv[1:], seg.words_dynamic[1:]
    c = lambda t, d: classify(t, d, seg.cwd, ctx)  # noqa: E731
    data = _data_positions(cmd, args)
    # an empty argument (e.g. macOS `sed -i ''`) can never name a file
    data |= {i for i, (a, d) in enumerate(zip(args, dyn)) if a == "" and not d}
    ops = _operands([a for i, a in enumerate(args) if i not in data], [d for i, d in enumerate(dyn) if i not in data])

    # everything else mentioned is a potential read (catches `cat .env`, `F=.env`, `source x`)
    for a, d in ops:
        u.reads.append(c(a, d))
    for i, (a, d) in enumerate(zip(args, dyn)):
        if i in data:
            continue
        if a.startswith("--") and "=" in a:
            u.reads.append(c(a.split("=", 1)[1], d))
        # curl -d @file, -F name=@file, httpie @file: the file is read and sent
        at = a.rfind("@")
        if at >= 0 and (at == 0 or a[at - 1] in "=<") and len(a) > at + 1:
            u.reads.append(c(a[at + 1:].split(";", 1)[0], d))
    for _, v in seg.assignments:
        u.reads.append(c(v, False))
    if cmd and "=" in cmd and not args:  # assignment-only segment
        for part in seg.argv:
            u.reads.append(c(part.split("=", 1)[1], False))
    for op, target, d in seg.redirects:
        if op in (">", ">>", ">|", "&>", "&>>", "<>"):
            u.writes.append(c(target, d))
        if op in ("<", "<>"):
            u.reads.append(c(target, d))

    if cmd in DELETE_CMDS:
        u.deletes += [c(a, d) for a, d in ops]
        if any(re.fullmatch(r"-[a-zA-Z]*[rR][a-zA-Z]*|--recursive", a) for a in args):
            u.flags.add("recursive_delete")
    elif cmd == "mv":
        tdir = _opt_values(args, dyn, ["-t", "--target-directory"])
        if tdir:
            u.writes += [c(a, d) for a, d in tdir]
            u.deletes += [c(a, d) for a, d in ops if (a, d) not in tdir]
        elif len(ops) >= 2:
            u.deletes += [c(a, d) for a, d in ops[:-1]]
            u.writes.append(c(*ops[-1]))
    elif cmd in ("cp", "install", "ln", "rsync", "scp", "ditto"):
        tdir = _opt_values(args, dyn, ["-t", "--target-directory"])
        if tdir:
            u.writes += [c(a, d) for a, d in tdir]
        elif len(ops) >= 2:
            a, d = ops[-1]
            if not _SCPLIKE.match(a):
                u.writes.append(c(a, d))
    elif cmd in ("tee", "touch", "mkdir", "truncate", "mkfifo", "mknod"):
        u.writes += [c(a, d) for a, d in ops if not (cmd == "truncate" and re.fullmatch(r"[+\-<>/%]?\d+[KMGTPkmgtp]?", a))]
    elif cmd in ("chmod", "chown", "chgrp"):
        u.writes += [c(a, d) for a, d in ops[1:]]
    elif cmd == "dd":
        for a, d in zip(args, dyn):
            if a.startswith("of="):
                u.writes.append(c(a[3:], d))
    elif cmd in ("sed", "gsed", "perl") and any(a == "-i" or a.startswith(("-i", "--in-place")) or
                                                  (cmd == "perl" and re.fullmatch(r"-[a-zA-Z]*i[a-zA-Z.]*", a)) for a in args):
        script_in_ops = cmd == "perl" and not any(a in ("-e", "-E") or re.fullmatch(r"-[a-zA-Z]*[eE][a-zA-Z.]*", a) for a in args)
        files = ops[1:] if script_in_ops else ops  # sed's script is already excluded as data
        u.writes += [c(a, d) for a, d in files]
    elif cmd == "curl":
        u.writes += [c(a, d) for a, d in _opt_values(args, dyn, ["-o", "--output"])]
    elif cmd == "wget":
        u.writes += [c(a, d) for a, d in _opt_values(args, dyn, ["-O", "--output-document", "-P", "--directory-prefix"])
                     if a != "-"]
    elif cmd == "tar":
        u.writes += [c(a, d) for a, d in _opt_values(args, dyn, ["-C", "--directory"])]
    elif cmd == "git" and args[:1] == ["clone"]:
        rest = _operands(args[1:], dyn[1:])
        if len(rest) >= 2:
            u.writes.append(c(*rest[1]))
    elif cmd == "find" and "-delete" in args:
        roots = []
        for a, d in zip(args, dyn):
            if a.startswith(("-", "(", "!")):
                break
            roots.append((a, d))
        u.deletes += [c(a, d) for a, d in (roots or [(".", False)])]
        u.flags.add("find_delete")

    for a in seg.argv + [seg.inline_code or ""]:
        u.hosts += _hosts_in(a)
    if cmd in FETCHERS or cmd in ("ssh", "sftp", "ftp", "mosh"):
        for a, _ in ops:
            if "://" in a:
                continue
            m = _SCPLIKE.match(a)
            if m:
                u.hosts.append(m.group(1).lower())
            elif re.fullmatch(r"(?:[\w.\-]+@)?[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?::\d+)?(?:/\S*)?|localhost(?::\d+)?(?:/\S*)?", a):
                h = _host(a.split("@", 1)[-1])
                if h:
                    u.hosts.append(h)
    elif cmd in ("scp", "rsync") or (cmd == "git" and args[:1] in (["clone"], ["fetch"], ["pull"], ["push"], ["remote"])):
        for a, _ in ops:
            m = _SCPLIKE.match(a)
            if m and "://" not in a:
                u.hosts.append(m.group(1).lower())
    if seg.inline_code:
        # paths named inside inline code (e.g. python -c "open('.env')") are potential reads
        for lit in re.findall(r"""['"]([^'"\s]{1,300})['"]""", seg.inline_code):
            u.reads.append(c(lit, False))

    if seg.dynamic_cmd:
        u.flags.add("dynamic_command")
    if seg.inline_code is not None:
        u.flags.add("inline_code")
    if seg.runs_script:
        u.flags.add("runs_script")
    if seg.args_dynamic:
        u.flags.add("args_dynamic")
    if seg.git_config_override:
        u.flags.add("git_config_override")
    return u


def build_units(tool: str, tool_input: dict, ctx: Context, raw: dict | None = None) -> list[Unit]:
    raw = raw or {}
    ti = tool_input if isinstance(tool_input, dict) else {}
    if tool == "Bash":
        command = str(ti.get("command", ""))
        parsed = parse_shell(command, cwd=ctx.cwd, env={"HOME": ctx.home, **({"TMPDIR": ctx.env["TMPDIR"]} if ctx.env.get("TMPDIR") else {})})
        cu = Unit("Bash", "command", command, label="(whole command)")
        cu.parsed = parsed
        units = [cu]
        units += [analyze_segment(s, ctx) for s in parsed.segments]
        return units

    u = Unit(tool, "tool", tool)
    c = lambda t: classify(t, False, ctx.cwd, ctx)  # noqa: E731
    fp = ti.get("file_path") or ti.get("notebook_path")
    if tool in ("Read", "NotebookRead"):
        if isinstance(fp, str):
            u.reads.append(c(fp))
    elif tool in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        if isinstance(fp, str):
            u.writes.append(c(fp))
    elif tool in ("Glob", "Grep", "LS"):
        base = ti.get("path") if isinstance(ti.get("path"), str) else ctx.cwd
        u.reads.append(c(base))
        if tool == "Grep" and isinstance(ti.get("glob"), str):
            u.reads.append(classify(os.path.join(base, ti["glob"]), False, ctx.cwd, ctx))
    elif tool == "WebFetch":
        h = _host(str(ti.get("url", "")))
        u.hosts.append(h or "(invalid-url)")
    elif tool.startswith("mcp__"):
        src = raw.get("mcp_server")
        u.mcp_source = src.get("source") if isinstance(src, dict) else None
    else:
        for k in ("file_path", "notebook_path", "path", "filePath", "directory"):
            if isinstance(ti.get(k), str):
                u.writes.append(c(ti[k]))  # unknown tool touching a path: assume it may write
    u.text = str(fp or ti.get("url") or ti.get("path") or tool)
    u.label = f"{tool}: {u.text}" if u.text != tool else tool
    return [u]


# ---------------------------------------------------------------- globs

def _glob_to_regex(pat: str) -> str:
    out, i = [], 0
    while i < len(pat):
        ch = pat[i]
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif ch == "*":
            out.append("[^/]*")
            i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        elif ch == "[":
            j = pat.find("]", i + 1)
            if j < 0:
                out.append(re.escape(ch))
                i += 1
            else:
                body = pat[i + 1:j].replace("\\", "\\\\")
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append(f"[{body}]")
                i = j + 1
        else:
            out.append(re.escape(ch))
            i += 1
    return "".join(out)


class PathPattern:
    def __init__(self, pattern: str):
        self.pattern = pattern
        self.basename_only = "/" not in pattern.replace("**/", "", 1) if pattern.startswith("**/") else "/" not in pattern
        self._compiled: dict[tuple, re.Pattern] = {}

    def regex(self, ctx: Context) -> re.Pattern:
        key = (ctx.project, ctx.home, ctx.ledger_home)
        rx = self._compiled.get(key)
        if rx is None:
            p = self.pattern.replace("{project}", ctx.project).replace("{ledger_home}", ctx.ledger_home)
            if p.startswith("~"):
                p = ctx.home + p[1:]
            if p.startswith("/"):
                lit = re.split(r"[*?\[]", p, 1)[0]
                head = lit.rsplit("/", 1)[0] if "/" in lit else lit
                if head:
                    real = os.path.realpath(head)
                    p = real + p[len(head):]
            elif self.basename_only and not p.startswith("**/"):
                p = "**/" + p
            rx = re.compile(_glob_to_regex(p), re.I | re.S)
            self._compiled[key] = rx
        return rx

    def match_str(self, candidate: str, ctx: Context) -> bool:
        return self.regex(ctx).fullmatch(candidate) is not None


GLOB_MAX_RESULTS = 500
# Names a wildcard is checked against when we refuse to walk directories for it.
_SENSITIVE_SAMPLES = (".env", ".env.local", ".env.production", "id_rsa", "id_ed25519", "id_ecdsa", "server.pem",
                      "server.key", "credentials", ".netrc", ".pgpass", "ledger.db", "settings.json",
                      "settings.local.json", ".agent-ledger.toml", "terraform.tfvars")


def path_candidates(ref: PathRef) -> list[str]:
    """Concrete strings a path reference may denote: its resolved path, its basename, and for
    globs the files it expands to. Globs are expanded only within ONE directory (bounded work:
    a slow hook times out and fails open); a wildcard in a directory component is instead
    checked against a list of sensitive file names."""
    import itertools

    cands = []
    if ref.resolved:
        cands.append(ref.resolved)
    if not ref.text:
        return cands
    last = ref.text.rstrip("/").rsplit("/", 1)[-1]
    cands.append("/" + last)
    if ref.resolved and ref.cwd and any(ch in ref.text for ch in "*?["):
        dir_part = ref.text.rstrip("/").rsplit("/", 1)[0] if "/" in ref.text.rstrip("/") else ""
        if any(ch in dir_part for ch in "*?["):
            rx = re.compile(_glob_to_regex(last), re.I)
            cands += ["/" + s for s in _SENSITIVE_SAMPLES if rx.fullmatch(s)]
        else:
            try:
                pattern = ref.text if os.path.isabs(ref.text) else os.path.join(ref.cwd, ref.text)
                it = _glob.iglob(os.path.expanduser(pattern))  # like bash: * skips dotfiles
                cands += [os.path.realpath(x) for x in itertools.islice(it, GLOB_MAX_RESULTS)]
            except (OSError, ValueError, TypeError):
                pass
    return cands


# ---------------------------------------------------------------- checks

def _is_shell_reader(seg: Segment) -> bool:
    return seg.stdin_shell or (seg.cmd in ("xargs",)) or (seg.cmd in SHELLS and not seg.runs_script)


def _check_remote_pipe(u: Unit, ctx: Context) -> bool:
    parsed = u.parsed
    for pipeline in parsed.pipelines:
        fetched = False
        for seg in pipeline:
            if seg.cmd in FETCHERS:
                fetched = True
            elif fetched and _is_shell_reader(seg):
                return True
    for seg in parsed.segments:
        if seg.sub_fetch and (seg.cmd in SHELLS or seg.cmd in INTERPRETERS or seg.cmd in ("source", ".", "eval")
                              or seg.dynamic_cmd or re.match(r"^(python|node|perl|ruby|php)[0-9.]*$", seg.cmd)):
            return True
    return False


def _check_pipe_to_shell(u: Unit, ctx: Context) -> bool:
    return any(seg.position > 0 and seg.stdin_shell for seg in u.parsed.segments)


def _git_push_protected(u: Unit, ctx: Context) -> bool:
    seg = u.segment
    if seg is None or seg.cmd != "git" or seg.argv[1:2] != ["push"]:
        return False
    args = seg.argv[2:]
    force = any(
        a in ("--force", "-f", "--force-if-includes", "--mirror", "--prune")
        or a.startswith("--force-with-lease")
        or re.fullmatch(r"-[a-zA-Z]*f[a-zA-Z]*", a)
        for a in args
    )
    delete = any(a in ("--delete", "-d") for a in args)
    positional = [a for a in args if not a.startswith("-")]
    refspecs = positional[1:]
    if any(r.startswith("+") for r in refspecs):
        force = True
    if any(r.startswith(":") for r in refspecs):
        delete = True
    if not (force or delete):
        return False
    if "--all" in args or "--mirror" in args:
        return True
    if not refspecs:
        from agent_ledger.gitinfo import git_info

        branch, _ = git_info(seg.cwd or ctx.cwd)
        return branch is None or branch in ctx.protected
    for r in refspecs:
        dst = r.lstrip("+").split(":")[-1]
        dst = dst[len("refs/heads/"):] if dst.startswith("refs/heads/") else dst
        if dst in ctx.protected or dst in ("HEAD", "@"):
            if dst in ("HEAD", "@"):
                from agent_ledger.gitinfo import git_info

                branch, _ = git_info(seg.cwd or ctx.cwd)
                if branch is not None and branch not in ctx.protected:
                    continue
            return True
    return False


def _chmod_world_writable(u: Unit, ctx: Context) -> bool:
    seg = u.segment
    if seg is None or seg.cmd != "chmod":
        return False
    for a in seg.argv[1:]:
        if a.startswith("-") and not re.fullmatch(r"-[rwxXst]+", a):
            continue
        if re.fullmatch(r"0*[0-7]{3,4}", a) and int(a[-1]) in (2, 3, 6, 7):
            return True
        if re.search(r"(^|,)[ugo]*[ao][ugo]*[+=][rwxXst]*w", a) or re.search(r"(^|,)a?[+=][rwxXst]*w", a) and a.startswith(("a", "=")):
            return True
        break
    return False


def _too_many_deletes(u: Unit, ctx: Context) -> bool:
    if u.segment is not None and u.segment.cmd in DELETE_CMDS and "args_dynamic" in u.flags:
        return True  # xargs rm / find -exec rm: targets only known at runtime
    if not u.deletes:
        return False
    if "recursive_delete" in u.flags or "find_delete" in u.flags or "args_dynamic" in u.flags:
        return True
    if any(any(ch in d.text for ch in "*?[") for d in u.deletes):
        return True
    return len(u.deletes) > ctx.max_delete


CHECKS = {
    "remote_pipe_to_shell": _check_remote_pipe,
    "pipe_to_shell": _check_pipe_to_shell,
    "unparseable": lambda u, ctx: u.parsed is not None and u.parsed.unparseable is not None,
    "delete_outside_project": lambda u, ctx: any(d.cls in ("outside", "root") for d in u.deletes),
    "write_outside_project": lambda u, ctx: any(w.cls == "outside" for w in u.writes),
    "unknown_write_target": lambda u, ctx: any(p.cls == "unknown" for p in u.writes + u.deletes),
    "too_many_deletes": _too_many_deletes,
    "git_force_push_protected": _git_push_protected,
    "chmod_world_writable": _chmod_world_writable,
    "dynamic_command": lambda u, ctx: "dynamic_command" in u.flags,
    "inline_code": lambda u, ctx: "inline_code" in u.flags,
    "runs_script": lambda u, ctx: "runs_script" in u.flags,
    "git_config_override": lambda u, ctx: "git_config_override" in u.flags,
}


# ---------------------------------------------------------------- rules

def _domain_ok(host: str, allowed: list[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in allowed)


class Rule:
    def __init__(self, data: dict, index: int):
        unknown = set(data) - RULE_KEYS
        if unknown:
            raise PolicyError(f"rule #{index + 1}: unknown key(s) {sorted(unknown)}")
        self.id = data.get("id")
        if not isinstance(self.id, str) or not self.id:
            raise PolicyError(f"rule #{index + 1}: missing 'id'")
        where = f"rule {self.id!r}"
        self.description = str(data.get("description", ""))
        self.decision = data.get("decision")
        if self.decision not in DECISIONS:
            raise PolicyError(f"{where}: decision must be one of {DECISIONS}")
        self.severity = data.get("severity", DEFAULT_SEVERITY[self.decision])
        if self.severity not in SEVERITIES:
            raise PolicyError(f"{where}: severity must be one of {SEVERITIES}")
        self.reason = str(data.get("reason") or self.description or self.id)

        def strlist(key):
            v = data.get(key)
            if v is None:
                return None
            if isinstance(v, str):
                v = [v]
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                raise PolicyError(f"{where}: '{key}' must be a string or list of strings")
            return v

        self.tools = strlist("tools")
        self._tool_res = []
        for t in self.tools or []:
            try:
                self._tool_res.append(re.compile(t[3:]) if t.startswith("re:") else None)
            except re.error as e:
                raise PolicyError(f"{where}: bad tool regex {t!r}: {e}") from e
        self.commands = strlist("commands")
        try:
            self.command = [re.compile(p) for p in (strlist("command") or [])]
        except re.error as e:
            raise PolicyError(f"{where}: bad command regex: {e}") from e
        self.paths = [PathPattern(p) for p in (strlist("paths") or [])]
        self.exclude = [PathPattern(p) for p in (strlist("exclude_paths") or [])]
        self.access = data.get("access", "any")
        if self.access not in ("read", "write", "delete", "any"):
            raise PolicyError(f"{where}: access must be read, write, delete or any")
        self.within_project = data.get("within_project")
        if self.within_project not in (None, True, False):
            raise PolicyError(f"{where}: within_project must be true or false")
        d = data.get("domains")
        if d is not None and not (d in ("allowlisted", "not_allowlisted") or (isinstance(d, list) and all(isinstance(x, str) for x in d))):
            raise PolicyError(f"{where}: domains must be \"allowlisted\", \"not_allowlisted\" or a list of domains")
        self.domains = d
        self.checks = strlist("check") or []
        for ch in self.checks:
            if ch not in CHECKS:
                raise PolicyError(f"{where}: unknown check {ch!r} (known: {sorted(CHECKS)})")
        levels = {ch in COMMAND_LEVEL_CHECKS for ch in self.checks}
        if len(levels) > 1:
            raise PolicyError(f"{where}: cannot mix command-level checks {sorted(COMMAND_LEVEL_CHECKS)} with others")
        self.command_level = levels == {True}
        if self.command_level and (self.commands or self.paths or self.domains or self.within_project is not None):
            raise PolicyError(f"{where}: command-level checks can only be combined with 'tools' and 'command'")
        self.mcp_source = strlist("mcp_source")

    def _tool_ok(self, tool: str) -> bool:
        if self.tools is None:
            return True
        for t, rx in zip(self.tools, self._tool_res):
            if rx is not None:
                if rx.fullmatch(tool):
                    return True
            elif t == tool or fnmatch.fnmatchcase(tool, t):
                return True
        return False

    def _paths_for(self, u: Unit) -> list[PathRef]:
        if self.access == "read":
            return u.reads
        if self.access == "write":
            return u.writes + u.deletes
        if self.access == "delete":
            return u.deletes
        return u.all_paths()

    def matches(self, u: Unit, ctx: Context) -> bool:
        if (u.level == "command") != self.command_level:
            return False
        if not self._tool_ok(u.tool):
            return False
        if self.mcp_source is not None and u.mcp_source not in self.mcp_source:
            return False
        if self.commands is not None:
            if u.segment is None or not any(fnmatch.fnmatchcase(u.segment.cmd, c) for c in self.commands):
                return False
        if self.command and not any(rx.search(u.text) for rx in self.command):
            return False
        if self.paths:
            hit = False
            for r in self._paths_for(u):
                for cand in path_candidates(r):
                    if any(e.match_str(cand, ctx) for e in self.exclude):
                        continue
                    if any(p.match_str(cand, ctx) for p in self.paths):
                        hit = True
                        break
                if hit:
                    break
            if not hit:
                return False
        if self.within_project is not None:
            refs = u.all_paths()
            inside = (all(r.cls in ("inside", "root", "temp", "special") for r in refs)
                      and not u.flags & {"dynamic_command", "args_dynamic"})
            if inside != self.within_project:
                return False
        if self.domains is not None:
            if not u.hosts:
                return False
            if self.domains == "not_allowlisted":
                if all(_domain_ok(h, ctx.allowed_domains) for h in u.hosts):
                    return False
            elif self.domains == "allowlisted":
                if not all(_domain_ok(h, ctx.allowed_domains) for h in u.hosts):
                    return False
            elif not any(_domain_ok(h, [x.lower() for x in self.domains]) for h in u.hosts):
                return False
        for ch in self.checks:
            if not CHECKS[ch](u, ctx):
                return False
        return True


class Policy:
    def __init__(self, rules: list[Rule], settings: dict, source: str, digest: str, warnings=()):
        self.rules = rules
        self.settings = settings
        self.source = source
        self.hash = digest
        self.warnings = list(warnings)

    @property
    def default_decision(self) -> str:
        return self.settings.get("default_decision", "ask")


def _toml(text: str, source: str) -> dict:
    import tomllib

    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise PolicyError(f"{source}: invalid TOML: {e}") from e


def _cached_toml(text: str, source: str, cache_dir: Path | None) -> dict:
    """Parsed TOML, cached as JSON keyed by content hash (tomllib costs ~4 ms per hook call)."""
    if cache_dir is None:
        return _toml(text, source)
    import json

    f = Path(cache_dir) / f"policy-{_sha256(text.encode('utf-8'))}.json"
    try:
        return json.loads(f.read_text("utf-8"))
    except (OSError, ValueError):
        pass
    data = _toml(text, source)
    try:
        Path(cache_dir).mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = f.with_name(f.name + f".{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, default=str)
        os.replace(tmp, f)
    except OSError:
        pass
    return data


def parse_policy(text: str, source: str = "<string>", cache_dir: Path | None = None) -> Policy:
    data = _cached_toml(text, source, cache_dir)
    unknown = set(data) - {"settings", "rule"}
    if unknown:
        raise PolicyError(f"{source}: unknown top-level key(s) {sorted(unknown)}")
    settings = data.get("settings", {})
    if not isinstance(settings, dict):
        raise PolicyError(f"{source}: [settings] must be a table")
    bad = set(settings) - SETTINGS_KEYS
    if bad:
        raise PolicyError(f"{source}: unknown setting(s) {sorted(bad)}")
    if settings.get("default_decision", "ask") not in DECISIONS:
        raise PolicyError(f"{source}: default_decision must be one of {DECISIONS}")
    for k in ("allowed_domains", "protected_branches", "temp_dirs"):
        v = settings.get(k)
        if v is not None and not (isinstance(v, list) and all(isinstance(x, str) for x in v)):
            raise PolicyError(f"{source}: {k} must be a list of strings")
    if "max_delete_files" in settings and not (isinstance(settings["max_delete_files"], int) and settings["max_delete_files"] >= 0):
        raise PolicyError(f"{source}: max_delete_files must be a non-negative integer")
    raw_rules = data.get("rule", [])
    if not isinstance(raw_rules, list):
        raise PolicyError(f"{source}: use [[rule]] tables for rules")
    rules, seen = [], set()
    for i, r in enumerate(raw_rules):
        rule = Rule(r, i)
        if rule.id in seen:
            raise PolicyError(f"{source}: duplicate rule id {rule.id!r}")
        seen.add(rule.id)
        rules.append(rule)
    return Policy(rules, settings, source, _sha256(text.encode("utf-8")))


# ---------------------------------------------------------------- loading & trust

def builtin_policy(cache_dir: Path | None = None) -> Policy:
    p = parse_policy(STARTER.read_text("utf-8"), "builtin:starter", cache_dir)
    p.hash = "builtin:" + p.hash
    return p


def load_policy(project_dir: str | None, home: Path) -> Policy:
    """Repo policy (if trusted) -> user policy -> built-in starter. Never raises for bad files."""
    warnings: list[str] = []
    cache = Path(home) / "cache"
    if project_dir:
        repo = Path(project_dir) / REPO_POLICY
        if repo.is_file():
            try:
                data = repo.read_bytes()
                digest = _sha256(data)
                if is_trusted(repo, digest, home):
                    pol = parse_policy(data.decode("utf-8"), str(repo), cache)
                    return pol
                warnings.append(
                    f"{repo} is not trusted (new or changed since `agent-ledger policy trust`); ignoring it"
                )
            except (OSError, UnicodeDecodeError, PolicyError) as e:
                warnings.append(f"invalid repo policy, ignoring it: {e}")
    user = home / "policy.toml"
    if user.is_file():
        try:
            pol = parse_policy(user.read_text("utf-8"), str(user), cache)
            pol.warnings = warnings
            return pol
        except (OSError, UnicodeDecodeError, PolicyError) as e:
            warnings.append(f"invalid user policy, ignoring it: {e}")
    pol = builtin_policy(cache)
    warnings.append("no usable policy file found; using the built-in starter policy")
    pol.warnings = warnings
    return pol


# ---------------------------------------------------------------- evaluation

class Explanation:
    def __init__(self):
        self.units: list[tuple[str, str, str | None, str]] = []  # (level, label, rule_id, decision)


def evaluate(policy: Policy, tool: str, tool_input: dict, ctx: Context, raw: dict | None = None,
             explain: Explanation | None = None) -> Decision:
    units = build_units(tool, tool_input, ctx, raw)
    best: Decision | None = None
    for u in units:
        matched = None
        for rule in policy.rules:
            if rule.matches(u, ctx):
                matched = rule
                break
        if matched is not None:
            d = Decision(matched.decision, matched.id, matched.severity, matched.reason, policy.hash)
        elif u.level == "command":
            if explain is not None:
                explain.units.append((u.level, u.label, None, "-"))
            continue
        else:
            dd = policy.default_decision
            d = Decision(dd, "default", DEFAULT_SEVERITY[dd], f"no rule matched; default is {dd}", policy.hash)
        if explain is not None:
            explain.units.append((u.level, u.label, d.rule_id, d.decision))
        if best is None or RANK[d.decision] > RANK[best.decision]:
            best = d
    if best is None:
        dd = policy.default_decision
        best = Decision(dd, "default", DEFAULT_SEVERITY[dd], f"no rule matched; default is {dd}", policy.hash)
    return best
