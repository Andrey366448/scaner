from __future__ import annotations

import re
from abc import ABC
from bisect import bisect_right
from typing import Iterable

from secret_scanner.detectors.base import BaseDetector
from secret_scanner.models import Candidate, CandidateKind, SourceFragment
from secret_scanner.utils.strings import mask_secret


class RegexDetector(BaseDetector, ABC):
    patterns: Iterable[re.Pattern[str]]

    def detect(self, fragment: SourceFragment) -> list[Candidate]:
        results: list[Candidate] = []
        line_starts = self._line_starts(fragment.content)
        for pattern in self.patterns:
            for match in pattern.finditer(fragment.content):
                secret_value = self.extract_secret(match)
                line_start = bisect_right(line_starts, match.start())
                line_end = line_start + match.group(0).count("\n")
                span = fragment.span.model_copy(
                    update={
                        "line_start": line_start,
                        "line_end": line_end,
                        "col_start": self._column_start(line_starts, match.start()),
                        "col_end": self._column_end(line_starts, match.start(), match.end()),

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
    def _line_starts(content: str) -> list[int]:
        starts = [0]
        starts.extend(idx + 1 for idx, char in enumerate(content) if char == "\n")
        return starts

    @staticmethod
    def _column_start(line_starts: list[int], absolute_offset: int) -> int:
        line_start = line_starts[bisect_right(line_starts, absolute_offset) - 1]

        return absolute_offset - line_start + 1

    @staticmethod
    def _column_end(line_starts: list[int], start_offset: int, end_offset: int) -> int:
        line_start = line_starts[bisect_right(line_starts, start_offset) - 1]
        return end_offset - line_start + 1
