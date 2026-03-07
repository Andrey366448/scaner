from __future__ import annotations

import re
from abc import ABC
from typing import Iterable

from secret_scanner.detectors.base import BaseDetector
from secret_scanner.models import Candidate, CandidateKind, SourceFragment
from secret_scanner.utils.strings import mask_secret


class RegexDetector(BaseDetector, ABC):
    patterns: Iterable[re.Pattern[str]]

    def detect(self, fragment: SourceFragment) -> list[Candidate]:
        results: list[Candidate] = []
        for pattern in self.patterns:
            for match in pattern.finditer(fragment.content):
                secret_value = self.extract_secret(match)
                line_start = fragment.content[: match.start()].count("\n") + 1
                line_end = line_start + match.group(0).count("\n")
                span = fragment.span.model_copy(
                    update={
                        "line_start": line_start,
                        "line_end": line_end,
                        "col_start": self._column_start(fragment.content, match.start()),
                        "col_end": self._column_end(fragment.content, match.start(), match.end()),
                    }
                )
                results.append(
                    Candidate(
                        kind=CandidateKind.REGEX,
                        detector_id=self.detector_id,
                        span=span,
                        match_text=match.group(0),
                        secret_value=secret_value,
                        secret_masked=mask_secret(secret_value),
                        metadata=self.build_metadata(match, fragment),
                        confidence=self.base_confidence(match, fragment),
                    )
                )
        return results

    def extract_secret(self, match: re.Match[str]) -> str:
        return match.group(0)

    def base_confidence(self, match: re.Match[str], fragment: SourceFragment) -> float:
        return 0.7

    def build_metadata(self, match: re.Match[str], fragment: SourceFragment) -> dict:
        return {}

    @staticmethod
    def _column_start(content: str, absolute_offset: int) -> int:
        line_start = content.rfind("\n", 0, absolute_offset) + 1
        return absolute_offset - line_start + 1

    @staticmethod
    def _column_end(content: str, start_offset: int, end_offset: int) -> int:
        line_start = content.rfind("\n", 0, start_offset) + 1
        return end_offset - line_start + 1
