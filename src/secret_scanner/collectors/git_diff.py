from __future__ import annotations

from pathlib import Path

from secret_scanner.collectors.base import BaseCollector
from secret_scanner.config.models import AppConfig
from secret_scanner.models import SourceFragment, SourceSpan
from secret_scanner.utils.git import (
    GitError,
    get_repo_root,
    list_diff_files,
    resolve_revision_from_refspec,
    show_revision_file,
)
from secret_scanner.utils.paths import should_ignore_path
from secret_scanner.utils.strings import is_binary_bytes


class GitDiffCollector(BaseCollector):
    def __init__(self, refspec: str, config: AppConfig, cwd: str | Path | None = None) -> None:
        self.refspec = refspec
        self.config = config
        self.repo_root = get_repo_root(cwd)
        self.target_revision = resolve_revision_from_refspec(refspec)

    def collect(self) -> list[SourceFragment]:
        fragments: list[SourceFragment] = []
        for rel_path in list_diff_files(self.refspec, self.repo_root):
            path_obj = Path(rel_path)
            if should_ignore_path(path_obj, self.config.filters.ignore_paths):
                continue
            fragment = self._collect_revision_file(rel_path)
            if fragment is not None:
                fragments.append(fragment)
        return fragments

    def _collect_revision_file(self, rel_path: str) -> SourceFragment | None:
        try:
            raw = show_revision_file(self.target_revision, rel_path, self.repo_root)
        except GitError:
            return None
        size_kb = len(raw) / 1024
        if size_kb > self.config.scan.max_file_size_kb:
            return None
        if is_binary_bytes(raw):
            return None
        text = raw.decode("utf-8", errors="ignore")
        return SourceFragment(
            span=SourceSpan(path=Path(rel_path).as_posix(), line_start=1, line_end=max(1, text.count("\n") + 1)),
            content=text,
            file_type=Path(rel_path).suffix.lower().lstrip("."),
            is_binary=False,
        )
