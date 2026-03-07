from __future__ import annotations

import subprocess
from pathlib import Path


class GitError(RuntimeError):
    pass


def run_git(args: list[str], cwd: str | Path | None = None) -> str:
    process = subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd is not None else None,
        capture_output=True,
        text=True,
        check=False,
    )
    if process.returncode != 0:
        raise GitError(process.stderr.strip() or process.stdout.strip() or "git command failed")
    return process.stdout


def get_repo_root(cwd: str | Path | None = None) -> Path:
    output = run_git(["rev-parse", "--show-toplevel"], cwd=cwd).strip()
    return Path(output)


def list_staged_files(cwd: str | Path | None = None) -> list[str]:
    output = run_git(["diff", "--cached", "--name-only", "--diff-filter=ACMR"], cwd=cwd)
    return [line.strip() for line in output.splitlines() if line.strip()]


def list_diff_files(refspec: str, cwd: str | Path | None = None) -> list[str]:
    output = run_git(["diff", "--name-only", "--diff-filter=ACMR", refspec], cwd=cwd)
    return [line.strip() for line in output.splitlines() if line.strip()]


def show_staged_file(path: str, cwd: str | Path | None = None) -> bytes:
    process = subprocess.run(
        ["git", "show", f":{path}"],
        cwd=str(cwd) if cwd is not None else None,
        capture_output=True,
        check=False,
    )
    if process.returncode != 0:
        raise GitError(process.stderr.decode("utf-8", errors="ignore").strip() or "git show failed")
    return process.stdout


def show_revision_file(revision: str, path: str, cwd: str | Path | None = None) -> bytes:
    process = subprocess.run(
        ["git", "show", f"{revision}:{path}"],
        cwd=str(cwd) if cwd is not None else None,
        capture_output=True,
        check=False,
    )
    if process.returncode != 0:
        raise GitError(process.stderr.decode("utf-8", errors="ignore").strip() or "git show failed")
    return process.stdout


def resolve_revision_from_refspec(refspec: str) -> str:
    if "..." in refspec:
        return refspec.split("...")[-1].strip()
    if ".." in refspec:
        return refspec.split("..")[-1].strip()
    return refspec.strip()
