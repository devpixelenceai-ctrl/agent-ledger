"""Shell command normalisation for policy matching.

Turns a raw command string into flat `Segment`s (one per simple command), so that rules
cannot be dodged with quoting, escapes, wrappers or command chaining. It handles:
  - operators && || ; | |& & newlines, subshell parens, comments
  - quotes '...', "...", $'...' (ANSI-C, incl. \\x / octal escapes), backslash escapes,
    line continuations, $IFS used as a separator, simple brace expansion {a,b}
  - command substitution $(...) and `...`, process substitution <(...) >(...)
  - here-docs (bodies fed to a shell are parsed as commands)
  - wrappers: sudo, doas, env (incl. -S), nice, ionice, nohup, time, timeout, command,
    exec, builtin, stdbuf, chronic, unbuffer, caffeinate, setsid, flock, watch, xargs
  - nested shells: bash/sh/zsh/... -c 'STRING', eval ARGS, find -exec CMD ;
  - variable tracking for literal assignments (F=.env; cat $F) and $HOME/$PWD/$TMPDIR
  - `cd` tracking so relative paths resolve against the right directory

This is a best-effort static view of a Turing-complete language. Anything it cannot
see through is flagged (dynamic command, inline code, unparseable) so policy can ask.
"""

from __future__ import annotations

import os
import re

MAX_DEPTH = 8
MAX_LEN = 200_000

_OPS = ("&&", "||", ";;", ";&", "|&", "&>>", "&>", ">>", ">|", ">&", "<<<", "<<-", "<<", "<&", "<>", ">", "<", "|", "&", ";", "(", ")")
_REDIRECTS = {"&>>", "&>", ">>", ">|", ">&", "<<<", "<<-", "<<", "<&", "<>", ">", "<"}
_SEPARATORS = {"&&", "||", ";;", ";&", "&", ";", "\n", "(", ")"}
_PIPES = {"|", "|&"}
_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\+?=(.*)$", re.S)
_KEYWORDS = {"if", "then", "elif", "else", "fi", "do", "done", "while", "until", "!", "{", "}", "time", "coproc"}

SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "mksh", "ash", "fish", "busybox", "csh", "tcsh"}
INTERPRETERS = {
    # name: flags that take inline code
    "python": ("-c",), "pypy": ("-c",), "node": ("-e", "--eval", "-p", "--print"), "nodejs": ("-e", "--eval"),
    "deno": (), "bun": ("-e", "--eval"), "perl": ("-e", "-E"), "ruby": ("-e",), "php": ("-r",), "lua": ("-e",),
    "osascript": ("-e",), "Rscript": ("-e",), "pwsh": ("-c", "-Command"), "powershell": ("-c", "-Command"),
    "tclsh": (), "jshell": (), "irb": (), "awk": (), "gawk": (), "mawk": (), "nawk": (),
}
FETCHERS = {"curl", "wget", "fetch", "http", "https", "xh", "httpie", "aria2c", "lwp-request", "nc", "ncat", "socat", "telnet"}

# wrapper: (options that take a value, number of positional args before the command)
_WRAPPERS = {
    "sudo": ({"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T", "--user", "--group"}, 0),
    "doas": ({"-u", "-C"}, 0),
    "nice": ({"-n", "--adjustment"}, 0),
    "ionice": ({"-c", "-n", "-p", "-t"}, 0),
    "nohup": (set(), 0),
    "time": ({"-f", "-o", "--format", "--output"}, 0),
    "timeout": ({"-s", "--signal", "-k", "--kill-after"}, 1),
    "command": (set(), 0),
    "exec": ({"-a"}, 0),
    "builtin": (set(), 0),
    "stdbuf": ({"-i", "-o", "-e"}, 0),
    "chronic": (set(), 0),
    "unbuffer": (set(), 0),
    "caffeinate": ({"-t", "-w"}, 0),
    "setsid": (set(), 0),
    "flock": ({"-w", "-E", "--timeout", "--conflict-exit-code"}, 1),
    "strace": ({"-e", "-o", "-p", "-s", "-u"}, 0),
    "ltrace": ({"-e", "-o", "-p", "-s", "-u"}, 0),
    "torsocks": (set(), 0),
    "proxychains": ({"-f"}, 0),
    "proxychains4": ({"-f"}, 0),
}
_XARGS_OPTS = {"-I", "-n", "-P", "-L", "-s", "-d", "-E", "-a", "--max-args", "--max-procs", "--delimiter", "--arg-file", "--replace"}


class ParseError(Exception):
    pass


# ---------------------------------------------------------------- lexer

class Word:
    """A shell word made of parts: ('lit', text) | ('var', name) | ('sub', index) | ('dyn', text)."""

    __slots__ = ("parts", "quoted", "glob")

    def __init__(self):
        self.parts: list[tuple[str, object]] = []
        self.quoted = False  # any quoted part (disables brace expansion / globbing of those chars)
        self.glob = False  # unquoted glob metacharacter present

    def lit(self, text: str, quoted: bool):
        if not quoted and any(c in text for c in "*?["):
            self.glob = True
        if quoted:
            self.quoted = True
        if self.parts and self.parts[-1][0] == "lit":
            self.parts[-1] = ("lit", self.parts[-1][1] + text)
        else:
            self.parts.append(("lit", text))

    def raw_literal(self) -> str | None:
        """Text if the word is fully literal (used for redirection operators/fd checks)."""
        if all(k == "lit" for k, _ in self.parts):
            return "".join(t for _, t in self.parts)
        return None


class Tok:
    __slots__ = ("kind", "value", "word", "heredoc")

    def __init__(self, kind, value=None, word=None):
        self.kind = kind  # "word" | "op"
        self.value = value
        self.word = word
        self.heredoc = None  # for << ops: dict(delim, strip, body)


_ANSI = re.compile(r"\\(x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|[0-7]{1,3}|c.|.)", re.S)
_ANSI_SIMPLE = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}


def _ansi_c(s: str) -> str:
    def rep(m):
        e = m.group(1)
        if e[0] in "xuU":
            return chr(int(e[1:], 16))
        if e[0] in "01234567":
            return chr(int(e, 8))
        if e[0] == "c":
            return chr(ord(e[1]) & 0x1F)
        return _ANSI_SIMPLE.get(e, e)

    return _ANSI.sub(rep, s)


def _match_close(s: str, i: int, open_: str, close: str) -> int:
    """Index of the bracket closing the one just before i, respecting quotes and nesting."""
    depth, n = 1, len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                raise ParseError("unterminated quote")
            i = j + 1
            continue
        if c == '"':
            i = _skip_dquote(s, i + 1)
            continue
        if c == "`":
            j = _find_backtick(s, i + 1)
            i = j + 1
            continue
        if c == open_:
            depth += 1
        elif c == close:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ParseError(f"unbalanced {open_}{close}")


def _skip_dquote(s: str, i: int) -> int:
    n = len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            return i + 1
        if c == "$" and i + 1 < n and s[i + 1] == "(":
            i = _match_close(s, i + 2, "(", ")") + 1
            continue
        if c == "`":
            i = _find_backtick(s, i + 1) + 1
            continue
        i += 1
    raise ParseError("unterminated double quote")


def _find_backtick(s: str, i: int) -> int:
    n = len(s)
    while i < n:
        if s[i] == "\\":
            i += 2
            continue
        if s[i] == "`":
            return i
        i += 1
    raise ParseError("unterminated backtick")


class Lexer:
    def __init__(self, s: str):
        self.s = s
        self.subs: list[tuple[str, str]] = []  # (kind, inner text)
        self.toks: list[Tok] = []
        self.cur: Word | None = None
        self.pending_heredocs: list[Tok] = []
        self.want_delim: Tok | None = None

    def _w(self) -> Word:
        if self.cur is None:
            self.cur = Word()
        return self.cur

    def _end(self):
        if self.cur is not None and self.cur.parts:
            self.toks.append(Tok("word", word=self.cur))
            if self.want_delim is not None:
                self.want_delim.heredoc["delim"] = "".join(str(t) for k, t in self.cur.parts if k == "lit")
                self.pending_heredocs.append(self.want_delim)
                self.want_delim = None
        self.cur = None

    def _sub(self, kind: str, inner: str) -> None:
        self.subs.append((kind, inner))
        self._w().parts.append(("sub", len(self.subs) - 1))

    def _dollar(self, i: int, quoted: bool) -> int:
        s, n = self.s, len(self.s)
        nxt = s[i + 1] if i + 1 < n else ""
        if nxt == "'" and not quoted:
            j = i + 2
            buf = []
            while j < n and s[j] != "'":
                if s[j] == "\\" and j + 1 < n:
                    buf.append(s[j:j + 2])
                    j += 2
                    continue
                buf.append(s[j])
                j += 1
            if j >= n:
                raise ParseError("unterminated $'")
            self._w().lit(_ansi_c("".join(buf)), True)
            return j + 1
        if nxt == "(":
            if i + 2 < n and s[i + 2] == "(":
                j = _match_close(s, i + 3, "(", ")")
                if j + 1 < n and s[j + 1] == ")":
                    self._w().parts.append(("dyn", s[i:j + 2]))
                    return j + 2
            j = _match_close(s, i + 2, "(", ")")
            self._sub("$(", s[i + 2:j])
            return j + 1
        if nxt == "{":
            j = _match_close(s, i + 2, "{", "}")
            inner = s[i + 2:j]
            name = re.match(r"[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-]", inner)
            if name and name.group(0) == "IFS" and inner == "IFS" and not quoted:
                self._end()
            elif name and name.end() == len(inner):
                self._w().parts.append(("var", name.group(0)))
            else:
                self._w().parts.append(("dyn", "${" + inner + "}"))
            return j + 1
        m = re.match(r"[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-]", s[i + 1:])
        if m:
            name = m.group(0)
            if name == "IFS" and not quoted:
                self._end()
            else:
                self._w().parts.append(("var", name))
            return i + 1 + len(name)
        self._w().lit("$", quoted)
        return i + 1

    def _dquote(self, i: int) -> int:
        s, n = self.s, len(self.s)
        w = self._w()
        w.quoted = True
        if not w.parts:
            w.parts.append(("lit", ""))
        while i < n:
            c = s[i]
            if c == '"':
                return i + 1
            if c == "\\" and i + 1 < n:
                nxt = s[i + 1]
                if nxt == "\n":
                    i += 2
                elif nxt in '$`"\\':
                    w.lit(nxt, True)
                    i += 2
                else:
                    w.lit("\\", True)
                    i += 1
                continue
            if c == "$":
                i = self._dollar(i, quoted=True)
                continue
            if c == "`":
                j = _find_backtick(s, i + 1)
                self._sub("`", s[i + 1:j])
                i = j + 1
                continue
            w.lit(c, True)
            i += 1
        raise ParseError("unterminated double quote")

    def _read_heredocs(self, i: int) -> int:
        s = self.s
        for tok in self.pending_heredocs:
            hd = tok.heredoc
            body = []
            while i < len(s):
                j = s.find("\n", i)
                line = s[i:] if j < 0 else s[i:j]
                i = len(s) if j < 0 else j + 1
                cmp_line = line.lstrip("\t") if hd["strip"] else line
                if cmp_line == hd["delim"]:
                    break
                body.append(line)
            hd["body"] = "\n".join(body)
        self.pending_heredocs = []
        return i

    def lex(self) -> list[Tok]:
        s, n, i = self.s, len(self.s), 0
        while i < n:
            c = s[i]
            if c in " \t":
                self._end()
                i += 1
            elif c == "\\":
                if i + 1 < n and s[i + 1] == "\n":
                    i += 2
                elif i + 1 < n:
                    self._w().lit(s[i + 1], True)
                    i += 2
                else:
                    i += 1
            elif c == "\n":
                self._end()
                self.toks.append(Tok("op", "\n"))
                i = self._read_heredocs(i + 1)
            elif c == "#" and self.cur is None:
                j = s.find("\n", i)
                i = n if j < 0 else j
            elif c == "'":
                j = s.find("'", i + 1)
                if j < 0:
                    raise ParseError("unterminated single quote")
                w = self._w()
                w.lit(s[i + 1:j], True)
                w.quoted = True
                i = j + 1
            elif c == '"':
                i = self._dquote(i + 1)
            elif c == "$":
                i = self._dollar(i, quoted=False)
            elif c == "`":
                j = _find_backtick(s, i + 1)
                self._sub("`", s[i + 1:j])
                i = j + 1
            elif c in "<>" and i + 1 < n and s[i + 1] == "(" and self.cur is None:
                j = _match_close(s, i + 2, "(", ")")
                self._sub(c + "(", s[i + 2:j])
                i = j + 1
            elif c in "&|;()<>":
                fd = None
                if c in "<>" and self.cur is not None:
                    lit = self.cur.raw_literal()
                    if lit is not None and lit.isdigit():
                        fd, self.cur = lit, None
                self._end()
                op = next(o for o in _OPS if s.startswith(o, i))
                tok = Tok("op", op)
                self.toks.append(tok)
                i += len(op)
                if op in ("<<", "<<-"):
                    tok.heredoc = {"strip": op == "<<-", "delim": None, "body": ""}
                    self.want_delim = tok
            else:
                self._w().lit(c, False)
                i += 1
        self._end()
        if self.want_delim is not None:
            raise ParseError("here-doc without delimiter")
        return self.toks


# ---------------------------------------------------------------- segments

class Segment:
    __slots__ = (
        "argv", "words_dynamic", "origin", "cwd", "redirects", "assignments", "dynamic_cmd",
        "inline_code", "stdin_shell", "runs_script", "args_dynamic", "pipeline", "position",
        "sub_fetch", "git_config_override", "heredoc", "depth",
    )

    def __init__(self):
        self.argv: list[str] = []
        self.words_dynamic: list[bool] = []
        self.origin = "top"
        self.cwd: str | None = None
        self.redirects: list[tuple[str, str, bool]] = []  # (op, target, dynamic)
        self.assignments: list[tuple[str, str]] = []
        self.dynamic_cmd = False
        self.inline_code: str | None = None
        self.stdin_shell = False  # shell/interpreter reading code from stdin
        self.runs_script: str | None = None
        self.args_dynamic = False  # e.g. xargs appends unknown arguments
        self.pipeline = 0
        self.position = 0
        self.sub_fetch = False  # an argument is a substitution that downloads something
        self.git_config_override = False
        self.heredoc: str | None = None
        self.depth = 0

    @property
    def cmd(self) -> str:
        return self.argv[0] if self.argv else ""

    @property
    def text(self) -> str:
        return " ".join(self.argv)

    def __repr__(self):
        return f"Segment({self.text!r}, origin={self.origin})"


class Parsed:
    def __init__(self):
        self.segments: list[Segment] = []
        self.pipelines: list[list[Segment]] = []
        self.unparseable: str | None = None


def _basename(cmd: str) -> str:
    base = cmd.rsplit("/", 1)[-1] if "/" in cmd else cmd
    return base or cmd


def _brace_expand(text: str) -> list[str]:
    m = re.search(r"\{([^{}]*,[^{}]*)\}", text)
    if not m:
        return [text]
    out = []
    for alt in m.group(1).split(","):
        out.extend(_brace_expand(text[: m.start()] + alt + text[m.end():]))
    return out[:64]


def _interp_name(cmd: str) -> str | None:
    if cmd in INTERPRETERS:
        return cmd
    m = re.match(r"^(python|pypy|node|perl|ruby|php|lua)[0-9.]*$", cmd)
    return m.group(1) if m else None


class Parser:
    def __init__(self, cwd: str | None, env: dict | None):
        env = env or {}
        self.home = env.get("HOME") or os.path.expanduser("~")
        self.vars: dict[str, str] = {"HOME": self.home}
        if env.get("TMPDIR"):
            self.vars["TMPDIR"] = env["TMPDIR"]
        if env.get("USER"):
            self.vars["USER"] = env["USER"]
        self.cwd = cwd
        self.out = Parsed()
        self.pipeline_counter = 0

    # word finalisation --------------------------------------------------
    def _finalize(self, word: Word, subs, depth: int, origin: str) -> tuple[list[str], bool, bool]:
        """Return (expanded texts, dynamic, sub_fetch)."""
        buf, dynamic, sub_fetch = [], False, False
        for kind, val in word.parts:
            if kind == "lit":
                buf.append(val)
            elif kind == "var":
                if val == "PWD" and self.cwd:
                    buf.append(self.cwd)
                elif val in self.vars:
                    buf.append(self.vars[val])
                else:
                    buf.append("$" + str(val))
                    dynamic = True
            elif kind == "sub":
                skind, inner = subs[val]
                before = len(self.out.segments)
                self._parse_into(inner, depth + 1, f"{skind}…)")
                if any(s.cmd in FETCHERS for s in self.out.segments[before:]):
                    sub_fetch = True
                buf.append(f"{skind}…)" if skind != "`" else "`…`")
                dynamic = True
            else:
                buf.append(str(val))
                dynamic = True
        text = "".join(buf)
        texts = _brace_expand(text) if (not word.quoted and "{" in text and "," in text) else [text]
        return texts, dynamic, sub_fetch

    # parsing ------------------------------------------------------------
    def parse(self, command: str) -> Parsed:
        try:
            if len(command) > MAX_LEN:
                raise ParseError("command too long to analyse")
            self._parse_into(command, 0, "top")
        except (ParseError, RecursionError, ValueError, IndexError) as e:
            self.out.unparseable = str(e) or type(e).__name__
        return self.out

    def _parse_into(self, command: str, depth: int, origin: str) -> None:
        if depth > MAX_DEPTH:
            raise ParseError("nesting too deep")
        lx = Lexer(command)
        toks = lx.lex()
        subs = lx.subs
        simple: list[Tok] = []
        pipeline: list[Segment] = []

        def flush_simple():
            if simple:
                seg = self._simple(simple, subs, depth, origin)
                if seg is not None:
                    pipeline.append(seg)
                simple.clear()

        def flush_pipeline():
            flush_simple()
            if pipeline:
                self.pipeline_counter += 1
                for pos, seg in enumerate(pipeline):
                    seg.pipeline, seg.position = self.pipeline_counter, pos
                self.out.pipelines.append(list(pipeline))
                pipeline.clear()

        for t in toks:
            if t.kind == "op" and t.value in _SEPARATORS:
                flush_pipeline()
            elif t.kind == "op" and t.value in _PIPES:
                flush_simple()
            else:
                simple.append(t)
        flush_pipeline()

    def _simple(self, toks: list[Tok], subs, depth: int, origin: str) -> Segment | None:
        seg = Segment()
        seg.origin, seg.depth = origin, depth
        words: list[tuple[str, bool]] = []
        sub_fetch = False
        i = 0
        while i < len(toks):
            t = toks[i]
            if t.kind == "op" and t.value in _REDIRECTS:
                if t.heredoc is not None:
                    seg.heredoc = t.heredoc.get("body", "")
                    i += 2  # skip delimiter word
                    continue
                if i + 1 < len(toks) and toks[i + 1].kind == "word":
                    texts, dyn, sf = self._finalize(toks[i + 1].word, subs, depth, origin)
                    sub_fetch |= sf
                    target = texts[0]
                    if not (t.value in (">&", "<&") and (target.isdigit() or target == "-")):
                        seg.redirects.append((t.value, target, dyn))
                    i += 2
                    continue
                i += 1
                continue
            if t.kind == "word":
                texts, dyn, sf = self._finalize(t.word, subs, depth, origin)
                sub_fetch |= sf
                words.extend((x, dyn) for x in texts)
            i += 1

        # leading control keywords and assignments
        while words and words[0][0] in _KEYWORDS and not words[0][1]:
            words.pop(0)
        while words:
            m = _ASSIGN.match(words[0][0])
            if not m or words[0][0].startswith("="):
                break
            name, value = m.group(1), m.group(2)
            seg.assignments.append((name, value))
            if not words[0][1]:
                self.vars[name] = value
            else:
                self.vars.pop(name, None)
            words.pop(0)
        seg.sub_fetch = sub_fetch
        if not words:
            if seg.assignments or seg.redirects:
                seg.argv = [f"{n}={v}" for n, v in seg.assignments]
                seg.words_dynamic = [False] * len(seg.argv)
                seg.cwd = self.cwd
                self.out.segments.append(seg)
                return seg
            return None

        seg.argv = [w for w, _ in words]
        seg.words_dynamic = [d for _, d in words]
        seg.cwd = self.cwd
        self._normalise(seg, subs, depth)
        self.out.segments.append(seg)
        self._track_cd(seg)
        return seg

    def _track_cd(self, seg: Segment) -> None:
        if seg.cmd not in ("cd", "pushd"):
            return
        args = [a for a in seg.argv[1:] if not a.startswith("-")]
        dyn = any(d for a, d in zip(seg.argv[1:], seg.words_dynamic[1:]) if not a.startswith("-"))
        if not args:
            self.cwd = self.home
        elif dyn or args[0] == "-":
            self.cwd = None
        else:
            target = os.path.expanduser(args[0])
            if not os.path.isabs(target):
                target = os.path.join(self.cwd, target) if self.cwd else None
            self.cwd = os.path.normpath(target) if target else None

    # normalisation / unwrapping ------------------------------------------
    def _strip_options(self, argv, dyn, opts_with_value, positional):
        i = 1
        while i < len(argv):
            a = argv[i]
            if a == "--":
                i += 1
                break
            if a.startswith("-") and a != "-":
                if a in opts_with_value or (len(a) == 2 and a in opts_with_value):
                    i += 2
                else:
                    i += 1
                continue
            if "=" in a and _ASSIGN.match(a):  # env NAME=VALUE
                i += 1
                continue
            break
        i += positional
        return argv[i:], dyn[i:]

    def _normalise(self, seg: Segment, subs, depth: int) -> None:
        for _ in range(16):
            if not seg.argv:
                return
            if seg.words_dynamic[0]:
                seg.dynamic_cmd = True
                return
            cmd = _basename(seg.argv[0])
            seg.argv[0] = cmd
            if cmd == "env" and any(a in ("-S", "--split-string") or a.startswith("-S") for a in seg.argv[1:]):
                idx = next(i for i, a in enumerate(seg.argv) if a.startswith("-S") or a == "--split-string")
                rest = seg.argv[idx][2:] if len(seg.argv[idx]) > 2 and seg.argv[idx].startswith("-S") else " ".join(seg.argv[idx + 1:])
                self._recurse(rest, depth, "env -S")
                seg.argv, seg.words_dynamic = ["env"], [False]
                return
            if cmd == "command" and len(seg.argv) > 1 and seg.argv[1] in ("-v", "-V"):
                return
            if cmd in _WRAPPERS:
                opts, positional = _WRAPPERS[cmd]
                argv, dyn = self._strip_options(seg.argv, seg.words_dynamic, opts, positional)
                if not argv:
                    return
                seg.argv, seg.words_dynamic = list(argv), list(dyn)
                continue
            if cmd == "env":
                argv, dyn = self._strip_options(seg.argv, seg.words_dynamic, {"-u", "-C", "--unset", "--chdir"}, 0)
                if not argv:
                    return
                seg.argv, seg.words_dynamic = list(argv), list(dyn)
                continue
            if cmd == "xargs":
                argv, dyn = self._strip_options(seg.argv, seg.words_dynamic, _XARGS_OPTS, 0)
                seg.args_dynamic = True
                if not argv:
                    seg.argv, seg.words_dynamic = ["echo"], [False]
                    return
                seg.argv, seg.words_dynamic = list(argv), list(dyn)
                continue
            if cmd == "watch":
                argv, _ = self._strip_options(seg.argv, seg.words_dynamic, {"-n", "-d", "--interval"}, 0)
                if argv:
                    self._recurse(" ".join(argv), depth, "watch")
                return
            if cmd == "eval":
                if any(seg.words_dynamic[1:]):
                    seg.dynamic_cmd = True
                else:
                    self._recurse(" ".join(seg.argv[1:]), depth, "eval")
                return
            if cmd in ("source", "."):
                if any(seg.words_dynamic[1:2]):
                    seg.runs_script = seg.argv[1] if len(seg.argv) > 1 else None
                return
            if cmd in SHELLS:
                self._shell(seg, depth)
                return
            interp = _interp_name(cmd)
            if interp:
                self._interpreter(seg, interp)
                return
            if cmd == "find":
                self._find(seg, depth)
                return
            if cmd == "git":
                self._git(seg)
                return
            return

    def _recurse(self, text: str, depth: int, origin: str) -> None:
        saved = self.cwd
        self._parse_into(text, depth + 1, origin)
        self.cwd = saved

    def _shell(self, seg: Segment, depth: int) -> None:
        argv = seg.argv
        i = 1
        code_flag = stdin_flag = False
        while i < len(argv):
            a = argv[i]
            if a == "--":
                i += 1
                break
            if a.startswith("-") and len(a) > 1 and not a.startswith("--"):
                if "c" in a[1:]:
                    code_flag = True
                if "s" in a[1:]:
                    stdin_flag = True
                if a == "-o" or a == "-O":
                    i += 1
                i += 1
                continue
            if a.startswith("--"):
                i += 1
                continue
            if argv[0] == "busybox" and a in ("sh", "ash"):
                i += 1
                continue
            break
        rest = argv[i:]
        if code_flag:
            if rest:
                if seg.words_dynamic[i]:
                    seg.dynamic_cmd = True
                else:
                    self._recurse(rest[0], depth, f"{argv[0]} -c")
            return
        if rest and not stdin_flag and rest[0] not in ("-", "-s"):
            seg.runs_script = rest[0]
            if seg.words_dynamic[i]:
                seg.dynamic_cmd = True
        else:
            seg.stdin_shell = True
            if seg.heredoc:
                self._recurse(seg.heredoc, depth, f"{argv[0]} <<heredoc")

    def _interpreter(self, seg: Segment, interp: str) -> None:
        flags = INTERPRETERS.get(interp, ())
        argv = seg.argv
        if interp in ("awk", "gawk", "mawk", "nawk"):
            i = 1
            while i < len(argv) and argv[i].startswith("-"):
                if argv[i] in ("-f", "--file"):
                    seg.runs_script = argv[i + 1] if i + 1 < len(argv) else None
                    return
                i += 2 if argv[i] in ("-F", "-v", "--assign", "--field-separator") else 1
            prog = argv[i] if i < len(argv) else ""
            if re.search(r"system\s*\(|\|\s*getline|getline\s*<|print[f]?\b[^;}]*>|\|&|\"\s*\|", prog):
                seg.inline_code = prog
            return
        for i, a in enumerate(argv[1:], start=1):
            if a in flags or (interp == "perl" and re.fullmatch(r"-[a-zA-Z]*[eE][a-zA-Z]*", a)) or (
                interp == "python" and re.fullmatch(r"-[a-zA-Z]*c", a)
            ):
                seg.inline_code = argv[i + 1] if i + 1 < len(argv) else ""
                return
            if a == "-m" and interp == "python":
                return
            if interp == "deno" and a == "eval":
                seg.inline_code = " ".join(argv[i + 1:])
                return
            if not a.startswith("-"):
                seg.runs_script = a
                return
        seg.stdin_shell = True
        if seg.heredoc:
            seg.inline_code = seg.heredoc

    def _find(self, seg: Segment, depth: int) -> None:
        argv = seg.argv
        i = 1
        while i < len(argv):
            if argv[i] in ("-exec", "-execdir", "-ok", "-okdir"):
                j = i + 1
                while j < len(argv) and argv[j] not in (";", "+", "\\;"):
                    j += 1
                inner = argv[i + 1:j]
                if inner:
                    sub = Segment()
                    sub.argv = list(inner)
                    sub.words_dynamic = list(seg.words_dynamic[i + 1:j])
                    sub.origin, sub.cwd, sub.depth, sub.args_dynamic = "find -exec", seg.cwd, depth + 1, True
                    self._normalise(sub, [], depth + 1)
                    self.out.segments.append(sub)
                    self.out.pipelines.append([sub])
                i = j + 1
                continue
            i += 1

    def _git(self, seg: Segment) -> None:
        argv, dyn = seg.argv, seg.words_dynamic
        out, outdyn = ["git"], [False]
        i = 1
        while i < len(argv):
            a = argv[i]
            if a in ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"):
                if a == "-c" or a == "--config-env":
                    seg.git_config_override = True
                i += 2
                continue
            if a.startswith(("--git-dir=", "--work-tree=", "--namespace=", "--exec-path=", "--config-env=")):
                if a.startswith("--config-env="):
                    seg.git_config_override = True
                i += 1
                continue
            if a.startswith("-") and a not in ("--version", "--help"):
                i += 1
                continue
            break
        seg.argv, seg.words_dynamic = out + argv[i:], outdyn + dyn[i:]


def parse(command: str, cwd: str | None = None, env: dict | None = None) -> Parsed:
    return Parser(cwd, env if env is not None else dict(os.environ)).parse(command)
