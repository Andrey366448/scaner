from __future__ import annotations

from secret_scanner.filters.base import BaseFilter, FilterDecision
from secret_scanner.models import Candidate, SourceFragment


class InlineIgnoreFilter(BaseFilter):
    filter_id = "inline_ignore_filter"

    def __init__(self, markers: list[str]) -> None:
        self.markers = tuple(marker.lower() for marker in markers)

    def apply(self, candidate: Candidate, fragment: SourceFragment) -> FilterDecision:
        line_text = str(candidate.metadata.get("line_text", candidate.match_text)).lower()
        if any(marker in line_text for marker in self.markers):
            return FilterDecision(suppressed=True, reason="inline ignore marker")
        return FilterDecision(suppressed=False)
