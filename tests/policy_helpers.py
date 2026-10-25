import pytest

from agent_ledger.policy import Context, Explanation, builtin_policy, evaluate

POLICY = builtin_policy()


class Env:
    def __init__(self, tmp_path):
        self.home = tmp_path / "home"
        self.home.mkdir()
        self.project = tmp_path / "proj"
        self.project.mkdir()
        self.scratch = tmp_path / "scratch"
        self.scratch.mkdir()
        (self.project / "src").mkdir()
        (self.project / "README.md").write_text("hi")
        (self.project / ".env").write_text("SECRET=1")
        (self.project / ".env.example").write_text("SECRET=")
        self.ctx = Context(
            str(self.project), cwd=str(self.project), env={"HOME": str(self.home)},
            settings={**POLICY.settings, "temp_dirs": [str(self.scratch)]},
        )

    def decide(self, command=None, tool="Bash", policy=POLICY, raw=None, explain=None, **tool_input):
        if command is not None:
            tool_input["command"] = command
        return evaluate(policy, tool, tool_input, self.ctx, raw=raw, explain=explain)

    def fmt(self, s: str) -> str:
        return s.replace("{home}", str(self.home)).replace("{proj}", str(self.project)).replace("{scratch}", str(self.scratch))


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)
