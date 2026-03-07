from __future__ import annotations

from pathlib import Path
from fnmatch import fnmatch


def should_ignore_path(path: Path, ignore_patterns: list[str]) -> bool:
    path_str = path.as_posix()
    name = path.name
    for pattern in ignore_patterns:
        if fnmatch(path_str, pattern) or fnmatch(name, pattern):
            return True
    return False
