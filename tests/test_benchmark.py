"""Latency budget: each hook call must finish in < 50 ms at p95 (it runs before every tool call).

Spawns the real installed entry point, exactly as Claude Code does, against a ledger that
already holds thousands of events. Two budgets:

- The p95 includes Python interpreter start-up, which agent-ledger does not control and which
  varies a lot with hardware and load: measured at ~18 ms on an idle laptop, ~35-45 ms on the
  same laptop under load, and far more on shared CI runners. Each run therefore also samples a
  bare interpreter (interleaved, same conditions) so a failure shows whose time it was.
- Enforced by default (run it on an idle machine). CI sets AGENT_LEDGER_BENCH_ENFORCE=0 and
  only reports, because wall-clock budgets on shared runners are noise. The deterministic
  regression guard, test_hot_path_imports_stay_lean, is enforced everywhere.
"""

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from agent_ledger import store
from conftest import payload

P95_BUDGET_MS = float(os.environ.get("AGENT_LEDGER_BENCH_BUDGET_MS", "50"))
ENFORCE = os.environ.get("AGENT_LEDGER_BENCH_ENFORCE", "1") != "0"
RUNS = 80
FORBIDDEN_ON_HOT_PATH = {"argparse", "http.server", "dataclasses", "inspect", "typing", "traceback", "difflib", "_hashlib"}


def hook_cmd():
    exe = Path(sys.executable).parent / "agent-ledger"
    return [str(exe), "hook"] if exe.exists() else [sys.executable, "-m", "agent_ledger", "hook"]


def p95(samples):
    s = sorted(samples)
    return s[int(len(s) * 0.95) - 1]


@pytest.fixture(scope="module")
def warm_home(tmp_path_factory):
    # pip/pipx byte-compile on install; an editable checkout under PYTHONDONTWRITEBYTECODE
    # would otherwise recompile every module on every call and measure the wrong thing.
    import agent_ledger

    subprocess.run([sys.executable, "-m", "compileall", "-q", str(Path(agent_ledger.__file__).parent)], check=True)
    home = tmp_path_factory.mktemp("bench-home")
    conn = store.connect(home / "ledger.db")
    conn.execute("BEGIN")
    for i in range(3000):  # bulk-load prior history without per-row commits
        conn.execute(
            "INSERT INTO events (seq, ts, agent, session_id, event_type, prev_hash, row_hash) "
            "VALUES (?, 't', 'claude-code', 'old', 'PostToolUse', 'x', 'y')", (i + 1,))
    conn.execute("COMMIT")
    conn.close()
    return home


@pytest.mark.bench
@pytest.mark.parametrize("name", ["pre_bash", "pre_edit", "post_bash", "prompt"])
def test_hook_latency_p95(name, warm_home):
    env = {**os.environ, "AGENT_LEDGER_HOME": str(warm_home)}
    data = json.dumps(payload(name))
    cmd = hook_cmd()
    bare = [sys.executable, "-c", "pass"]
    for _ in range(3):
        subprocess.run(cmd, input=data, text=True, capture_output=True, env=env)
    samples, baseline = [], []
    for _ in range(RUNS):  # interleave so both series see the same machine conditions
        t = time.perf_counter()
        subprocess.run(bare, capture_output=True, env=env)
        baseline.append((time.perf_counter() - t) * 1000)
        t = time.perf_counter()
        r = subprocess.run(cmd, input=data, text=True, capture_output=True, env=env)
        samples.append((time.perf_counter() - t) * 1000)
        assert r.returncode == 0, r.stderr
    result, base = p95(samples), p95(baseline)
    overhead = result - base
    print(f"\n[bench] {name}: p50={sorted(samples)[RUNS // 2]:.1f}ms p95={result:.1f}ms "
          f"(bare interpreter p95={base:.1f}ms, agent-ledger overhead={overhead:.1f}ms)")
    if ENFORCE:
        assert result < P95_BUDGET_MS, (f"{name} p95 {result:.1f}ms exceeds {P95_BUDGET_MS}ms "
                                        f"(bare interpreter alone: {base:.1f}ms)")


@pytest.mark.skipif(bool(os.environ.get("COVERAGE_PROCESS_START")),
                    reason="subprocess coverage imports coverage (and inspect/typing) into every process")
def test_hot_path_imports_stay_lean():
    code = "import sys, agent_ledger.hook; print('\\n'.join(sys.modules))"
    mods = set(subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout.split())
    assert not (mods & FORBIDDEN_ON_HOT_PATH), mods & FORBIDDEN_ON_HOT_PATH
