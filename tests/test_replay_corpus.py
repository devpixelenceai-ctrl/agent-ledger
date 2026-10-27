"""Replay every decision from real recorded agent sessions (tests/corpus/real_sessions.jsonl).

A policy or parser change that alters how a real session would have been judged fails here. If the
change is intended, add the case to DELIBERATE_CHANGES with the reason, so drift is always reviewed.
Rebuild the corpus with tests/corpus/build_corpus.py.
"""

import json
from pathlib import Path

import pytest

from agent_ledger.policy import Context, builtin_policy, evaluate

CORPUS = Path(__file__).parent / "corpus" / "real_sessions.jsonl"
CASES = [json.loads(line) for line in CORPUS.read_text().splitlines() if line.strip()]
POLICY = builtin_policy()

# source -> (expected decision, expected rule, why it differs from what was recorded)
_F2 = "trial finding F2: legitimate test/lint runner needed approval; allowed inside the project since 0.1.0"
DELIBERATE_CHANGES: dict[str, tuple[str, str, str]] = {
    "django#5": ("allow", "shell.tests-and-linters", _F2),   # python tests/runtests.py
    "fastify#5": ("allow", "shell.tests-and-linters", _F2),  # node --test
    "hugo#49": ("allow", "shell.tests-and-linters", _F2),    # gofmt -l
}

# Note: decisions that depend on file *contents* (e.g. the git secret scan) are not reproduced here,
# because the original repos are not part of the corpus; those have dedicated tests in test_secretscan.py.


def _fill(obj, project, home):
    if isinstance(obj, str):
        return obj.replace("{project}", project).replace("{home}", home)
    if isinstance(obj, dict):
        return {k: _fill(v, project, home) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_fill(v, project, home) for v in obj]
    return obj


@pytest.fixture(scope="module")
def ctx(tmp_path_factory):
    root = tmp_path_factory.mktemp("replay")
    home, project = root / "home", root / "project"
    home.mkdir()
    project.mkdir()
    c = Context(str(project), cwd=str(project), env={"HOME": str(home)},
                settings={**POLICY.settings, "temp_dirs": [str(root / "scratch")]})
    return c, str(project), str(home)


def test_corpus_is_not_empty_and_portable():
    assert len(CASES) >= 40
    raw = CORPUS.read_text()
    assert "/Users/" not in raw and "/home/" not in raw  # only {project}/{home} placeholders


@pytest.mark.parametrize("case", CASES, ids=[c["source"] for c in CASES])
def test_real_session_decision_is_stable(ctx, case):
    c, project, home = ctx
    ti = _fill(case["tool_input"], project, home)
    d = evaluate(POLICY, case["tool"], ti, c)
    expected = DELIBERATE_CHANGES.get(case["source"])
    want = (expected[0], expected[1]) if expected else (case["recorded"]["decision"], case["recorded"]["rule"])
    assert (d.decision, d.rule_id) == want, f"{case['source']}: {case['tool']} {ti} -> {d.decision}/{d.rule_id}"
