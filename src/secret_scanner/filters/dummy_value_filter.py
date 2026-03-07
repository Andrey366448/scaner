from __future__ import annotations

from secret_scanner.filters.base import BaseFilter, FilterDecision
from secret_scanner.models import Candidate, SourceFragment


class DummyValueFilter(BaseFilter):
    filter_id = "dummy_value_filter"

    def __init__(self, dummy_values: list[str]) -> None:
        self.dummy_values = {value.strip().lower() for value in dummy_values}

    def apply(self, candidate: Candidate, fragment: SourceFragment) -> FilterDecision:
        value = candidate.secret_value.strip().lower()
        if value in self.dummy_values:
            return FilterDecision(suppressed=True, reason="dummy value")
        return FilterDecision(suppressed=False)
