import subprocess
from pathlib import Path

from secret_scanner.config.models import AppConfig
from secret_scanner.engine.factory import build_scanner


def run(cmd: list[str], cwd: Path) -> None:
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)


def init_repo(repo: Path) -> None:
    run(["git", "init"], repo)
    run(["git", "config", "user.email", "test@example.com"], repo)
    run(["git", "config", "user.name", "Test User"], repo)


def test_staged_collector_reads_index_content(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    init_repo(repo)

    target = repo / "app.py"
    target.write_text('TOKEN = "dummy"\n', encoding="utf-8")
    run(["git", "add", "app.py"], repo)
    run(["git", "commit", "-m", "init"], repo)

    target.write_text('TOKEN = "ghp_super_secret_token_value"\n', encoding="utf-8")
    run(["git", "add", "app.py"], repo)
    target.write_text('TOKEN = "dummy"\n', encoding="utf-8")

    monkeypatch.chdir(repo)
    result = build_scanner(["."], AppConfig(), staged=True, use_baseline=False).run()
    assert len(result.findings) == 1
    assert result.findings[0].span.path == "app.py"


def test_git_diff_collector_reads_target_revision(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    init_repo(repo)

    target = repo / "app.py"
    target.write_text('TOKEN = "dummy"\n', encoding="utf-8")
    run(["git", "add", "app.py"], repo)
    run(["git", "commit", "-m", "init"], repo)

    target.write_text('TOKEN = "ghp_super_secret_token_value"\n', encoding="utf-8")
    run(["git", "add", "app.py"], repo)
    run(["git", "commit", "-m", "add secret"], repo)

    monkeypatch.chdir(repo)
    result = build_scanner(["."], AppConfig(), git_diff="HEAD~1..HEAD", use_baseline=False).run()
    assert len(result.findings) == 1
    assert result.findings[0].span.path == "app.py"
