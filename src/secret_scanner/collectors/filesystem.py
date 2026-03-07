from __future__ import annotations

from pathlib import Path

from secret_scanner.collectors.base import BaseCollector
from secret_scanner.config.models import AppConfig
from secret_scanner.models import SourceFragment, SourceSpan
from secret_scanner.utils.paths import should_ignore_path
from secret_scanner.utils.strings import is_binary_bytes


class FilesystemCollector(BaseCollector):
    def __init__(self, paths: list[str], config: AppConfig) -> None:
        self.paths = [Path(p) for p in (paths or ["."])]
        self.config = config

    def collect(self) -> list[SourceFragment]:
        fragments: list[SourceFragment] = []
        for path in self.paths:
            if not path.exists():
                continue
            if path.is_dir():
                fragments.extend(self._collect_directory(path))
            else:
                fragment = self._collect_file(path)
                if fragment is not None:
                    fragments.append(fragment)
        return fragments

    def _collect_directory(self, directory: Path) -> list[SourceFragment]:
        fragments: list[SourceFragment] = []
        for file_path in directory.rglob("*"):
            if file_path.is_dir():
                continue
            if should_ignore_path(file_path, self.config.filters.ignore_paths):
                continue
            fragment = self._collect_file(file_path)
            if fragment is not None:
                fragments.append(fragment)
        return fragments

    def _collect_file(self, path: Path) -> SourceFragment | None:
        if should_ignore_path(path, self.config.filters.ignore_paths):
            return None
        if not self.config.scan.follow_symlinks and path.is_symlink():
            return None
        try:
            size_kb = path.stat().st_size / 1024
            if size_kb > self.config.scan.max_file_size_kb:
                return None
            raw = path.read_bytes()
        except (OSError, PermissionError):
            return None

        if is_binary_bytes(raw):
            return None

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="ignore")

        return SourceFragment(
            span=SourceSpan(path=str(path), line_start=1, line_end=max(1, text.count("\n") + 1)),
            content=text,
            file_type=path.suffix.lower().lstrip("."),
            is_binary=False,
        )
