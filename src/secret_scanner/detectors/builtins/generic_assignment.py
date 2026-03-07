from __future__ import annotations

import re
from collections import Counter
from math import log2

from secret_scanner.detectors.base import BaseDetector
from secret_scanner.models import Candidate, CandidateKind, SourceFragment
from secret_scanner.utils.strings import mask_secret

SUSPICIOUS_KEYS: dict[str, float] = {
    "password": 1.0,
    "passwd": 1.0,
    "pwd": 0.8,
    "secret": 1.0,
    "token": 0.9,
    "api_key": 1.0,
    "apikey": 1.0,
    "access_key": 0.9,
    "auth": 0.6,
    "credential": 0.8,
    "client_secret": 1.0,
}

ASSIGNMENT_RE = re.compile(
    r"(?P<key>[A-Za-z_][A-Za-z0-9_\-]{1,60})\s*(?:=|:|=>)\s*(?P<quote>['\"]?)(?P<value>[^'\"\n\r]{4,300})(?P=quote)"
)


class GenericAssignmentDetector(BaseDetector):
    detector_id = "generic_assignment"
    title = "Generic secret assignment"

    def detect(self, fragment: SourceFragment) -> list[Candidate]:
        results: list[Candidate] = []
        for match in ASSIGNMENT_RE.finditer(fragment.content):
            key = match.group("key")
            value = match.group("value").strip()
            key_weight = self._key_weight(key)
            if key_weight <= 0:
                continue
            entropy = self._entropy(value)
            confidence = 0.3 + key_weight
            if len(value) >= 12:
                confidence += 0.2
            if entropy >= 3.5:
                confidence += 0.2
            line_start = fragment.content[: match.start()].count("\n") + 1
            span = fragment.span.model_copy(
                update={
                    "line_start": line_start,
                    "line_end": line_start,
                }
            )
            results.append(
                Candidate(
                    kind=CandidateKind.KEYWORD_VALUE,
                    detector_id=self.detector_id,
                    span=span,
                    match_text=match.group(0),
                    secret_value=value,
                    secret_masked=mask_secret(value),
                    metadata={
                        "key": key,
                        "key_weight": key_weight,
                        "entropy": entropy,
                        "provider_known": False,
                    },
                    confidence=confidence,
                )
            )
        return results

    @staticmethod
    def _key_weight(key: str) -> float:
        normalized = key.lower()
        best = 0.0
        for suspicious_key, weight in SUSPICIOUS_KEYS.items():
            if suspicious_key in normalized:
                best = max(best, weight)
        return best

    @staticmethod
    def _entropy(value: str) -> float:
        if not value:
            return 0.0
        counts = Counter(value)
        length = len(value)
        return -sum((count / length) * log2(count / length) for count in counts.values())
