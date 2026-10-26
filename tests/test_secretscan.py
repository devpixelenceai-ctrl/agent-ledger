"""Finding F1 from the real-world trial: an agent committed a file full of credentials and
nothing stopped it. `git add` / `git commit` now scan the content about to be committed."""

import shutil
import subprocess
import time
from pathlib import Path

import pytest

from agent_ledger.policy import Context, builtin_policy, evaluate
from agent_ledger.secretscan import find_secrets, scan_git_command

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

POLICY = builtin_policy()
AWS = "AKIAQZ7XK3M9TB2PLW4R"
GH = "ghp_" + "Zq8Lm2Xv7Rp4Ws9Ky1Nb6Cf3Hj0Dz5Ga1B2c"
SECRET_KEY_LINE = 'SECRET_KEY = "django-insecure-9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"'


def git(repo, *args):
    return subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *args], cwd=repo,
                          capture_output=True, text=True, check=True).stdout


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "work")
    (r / "app.py").write_text("print('hello')\n")
    git(r, "add", "app.py")
    git(r, "commit", "-q", "-m", "init")
    return r


def decide(repo, cmd, home=None):
    ctx = Context(str(repo), cwd=str(repo), env={"HOME": str(home or repo.parent / "home")}, settings=POLICY.settings)
    return evaluate(POLICY, "Bash", {"command": cmd}, ctx)


# ---------------------------------------------------------------- detector

@pytest.mark.parametrize("text,kind", [
    (f"aws_key = '{AWS}'", "aws-access-key"),
    (f"token: {GH}", "github-token"),
    (SECRET_KEY_LINE, "secret-assignment"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", "private-key"),
    ("DATABASE_URL=postgres://app:S3cretPassw0rd@db:5432/app", "url-credentials"),
])
def test_detector_finds_secrets(text, kind):
    assert kind in find_secrets(text)


@pytest.mark.parametrize("text", [
    'password = "changeme"', "api_key = os.environ['API_KEY']", 'token = "${GITHUB_TOKEN}"',
    'secret = "<your-secret-here>"', 'password="test1234"', "max_tokens = 4096", "def get_token(self):",
    "row_hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'",
    'SECRET_KEY = "django-insecure-example-key-for-docs"', "print('hello')",
])
def test_detector_ignores_placeholders_and_code(text):
    assert find_secrets(text) == set()


# ---------------------------------------------------------------- policy decisions on real repos

def test_add_file_with_secret_asks_and_reason_has_no_value(repo):
    (repo / "settings.py").write_text(SECRET_KEY_LINE + f"\nAWS_ACCESS_KEY_ID = '{AWS}'\n")
    d = decide(repo, "git add settings.py")
    assert d.decision == "ask" and d.rule_id == "git.secret-in-commit"
    assert "settings.py" in d.reason and "aws-access-key" in d.reason
    assert AWS not in d.reason and "9f8e7d6c" not in d.reason


def test_the_trial_case_add_and_commit_chain(repo):
    (repo / "tests").mkdir()
    (repo / "tests" / "canary_settings.py").write_text(SECRET_KEY_LINE + "\n")
    d = decide(repo, "git add tests/canary_settings.py && git commit -m 'Add slugify unicode test'")
    assert d.decision == "ask"


def test_add_clean_file_is_allowed(repo):
    (repo / "util.py").write_text("def add(a, b):\n    return a + b\n")
    assert decide(repo, "git add util.py").decision == "allow"


def test_add_all_with_untracked_secret_asks(repo):
    (repo / "config").mkdir()
    (repo / "config" / "deploy.toml").write_text(f'github_token = "{GH}"\n')
    for cmd in ("git add -A", "git add .", "git add --all", "git add config/"):
        assert decide(repo, cmd).decision == "ask", cmd


def test_add_all_with_untracked_env_file_asks(repo):
    (repo / ".env.production").write_text("X=1\n")
    assert decide(repo, "git add -A").decision == "ask"


def test_modified_tracked_file_add_dot(repo):
    (repo / "app.py").write_text(f"print('hello')\nTOKEN = '{GH}'\n")
    assert decide(repo, "git add .").decision == "ask"


def test_commit_scans_staged_content(repo):
    (repo / "keys.py").write_text(f"AWS = '{AWS}'\n")
    git(repo, "add", "keys.py")
    assert decide(repo, "git commit -m 'add keys'").decision == "ask"


def test_commit_with_clean_staged_content_is_allowed(repo):
    (repo / "util.py").write_text("x = 1\n")
    git(repo, "add", "util.py")
    assert decide(repo, "git commit -m 'util'").decision == "allow"


def test_commit_all_scans_tracked_changes(repo):
    (repo / "app.py").write_text(f"print('hello')\nAWS = '{AWS}'\n")
    assert decide(repo, "git commit -am 'oops'").decision == "ask"
    assert decide(repo, "git commit -a -m 'oops'").decision == "ask"


def test_removing_a_secret_is_not_flagged(repo):
    (repo / "app.py").write_text(f"AWS = '{AWS}'\n")
    git(repo, "add", "app.py")
    git(repo, "commit", "-q", "-m", "had secret")
    (repo / "app.py").write_text("AWS = os.environ['AWS']\n")
    assert decide(repo, "git commit -am 'remove secret'").decision == "allow"


def test_not_a_git_repo_does_not_crash(tmp_path):
    d = tmp_path / "plain"
    d.mkdir()
    (d / "a.py").write_text("x = 1\n")
    assert decide(d, "git add a.py").decision in ("allow", "ask")


# ---------------------------------------------------------------- safety of the scan itself

def test_scan_never_runs_repo_configured_programs(repo, tmp_path):
    pwned = tmp_path / "pwned"
    (repo / ".gitattributes").write_text("*.py diff=evil\n")
    git(repo, "config", "diff.evil.textconv", f"touch {pwned}; cat")
    git(repo, "config", "diff.external", f"touch {pwned}")
    git(repo, "config", "core.fsmonitor", f"touch {pwned}")
    (repo / "app.py").write_text(f"AWS = '{AWS}'\n")
    git(repo, "add", "app.py")  # plain git: this setup step itself triggers the traps...
    pwned.unlink(missing_ok=True)  # ...so clear the marker before measuring our scan
    (repo / "more.py").write_text(f"GH = '{GH}'\n")
    assert decide(repo, "git commit -m x").decision == "ask"
    assert decide(repo, "git add -A").decision == "ask"
    assert decide(repo, "git commit -am x").decision == "ask"
    assert not pwned.exists(), "the scan ran a program configured by the repo"


def test_scan_is_bounded_on_large_changes(repo):
    for i in range(400):
        (repo / f"f{i}.txt").write_text("line\n" * 200)
    t = time.perf_counter()
    decide(repo, "git add -A")
    assert time.perf_counter() - t < 3


def test_scan_reports_findings_without_values(repo):
    (repo / "s.py").write_text(f"k = '{AWS}'\n")
    findings = scan_git_command(["git", "add", "s.py"], str(repo))
    assert findings and all(AWS not in f"{p}{k}" for p, k in findings)


def test_scan_never_runs_clean_filters(repo, tmp_path):
    # Clean filters run whenever git reads working files through its filter layer (add, diff, status).
    # The scan reads working files itself, so a repo-planted filter must never fire.
    pwned = tmp_path / "pwned-filter"
    (repo / ".gitattributes").write_text("*.cfg filter=evil\n")
    git(repo, "config", "filter.evil.clean", f"touch {pwned}; cat")
    (repo / "deploy.cfg").write_text(f"token = '{GH}'\n")
    (repo / "app.py").write_text(f"print(1)\nAWS = '{AWS}'\n")
    assert decide(repo, "git add -A").decision == "ask"
    assert decide(repo, "git add deploy.cfg").decision == "ask"
    assert decide(repo, "git commit -am x").decision == "ask"
    assert not pwned.exists(), "the scan ran a repo-configured clean filter"


@pytest.mark.parametrize("marker", ["# agent-ledger:allow-secret", "# gitleaks:allow"])
def test_inline_allow_marker_skips_that_line_only(repo, marker):
    (repo / "fixtures.py").write_text(f"FAKE = '{AWS}'  {marker}\n")
    assert decide(repo, "git add fixtures.py").decision == "allow"
    (repo / "fixtures.py").write_text(f"FAKE = '{AWS}'  {marker}\nREAL = '{GH}'\n")
    assert decide(repo, "git add fixtures.py").decision == "ask"
