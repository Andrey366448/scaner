from __future__ import annotations

from pathlib import Path

from secret_scanner.filters.base import BaseFilter, FilterDecision
from secret_scanner.models import Candidate, SourceFragment
from secret_scanner.utils.paths import should_ignore_path


class PathFilter(BaseFilter):
    filter_id = "path_filter"

    def __init__(self, ignore_paths: list[str]) -> None:
        self.ignore_paths = ignore_paths

    def apply(self, candidate: Candidate, fragment: SourceFragment) -> FilterDecision:
        if should_ignore_path(Path(fragment.span.path), self.ignore_paths):
            return FilterDecision(suppressed=True, reason="ignored path")
        return FilterDecision(suppressed=False)
