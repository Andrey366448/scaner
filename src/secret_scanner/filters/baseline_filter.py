from __future__ import annotations

from secret_scanner.baseline import fingerprint_candidate
from secret_scanner.filters.base import BaseFilter, FilterDecision
from secret_scanner.models import Candidate, SourceFragment


class BaselineFilter(BaseFilter):
    filter_id = "baseline_filter"

    def __init__(self, fingerprints: set[str]) -> None:
        self.fingerprints = fingerprints

    def apply(self, candidate: Candidate, fragment: SourceFragment) -> FilterDecision:
        fingerprint = fingerprint_candidate(candidate)
        if fingerprint in self.fingerprints:
            return FilterDecision(suppressed=True, reason="baseline match")
        return FilterDecision(suppressed=False)
