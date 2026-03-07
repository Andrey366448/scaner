from __future__ import annotations

from pathlib import Path

from secret_scanner.filters.base import BaseFilter, FilterDecision
from secret_scanner.models import Candidate, SourceFragment

TEST_HINTS = {"test", "tests", "fixture", "fixtures", "example", "examples", "sample", "samples", "docs"}
ALWAYS_REPORT = {"private_key"}


class TestContextFilter(BaseFilter):
    filter_id = "test_context_filter"

    def apply(self, candidate: Candidate, fragment: SourceFragment) -> FilterDecision:
        if candidate.detector_id in ALWAYS_REPORT:
            return FilterDecision(suppressed=False)
        path_parts = {part.lower() for part in Path(fragment.span.path).parts}
        if path_parts & TEST_HINTS:
            return FilterDecision(suppressed=True, reason="test/example context")
        return FilterDecision(suppressed=False)
