from __future__ import annotations

import re

from secret_scanner.detectors.base import BaseDetector
from secret_scanner.models import Candidate, CandidateKind, SourceFragment
from secret_scanner.utils.strings import mask_secret

ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    \b(?P<key>
        api[_-]?key|
        secret|
        token|
        password|passwd|pwd|
        auth(?:orization)?|
        access[_-]?token|
        refresh[_-]?token|
        client[_-]?secret
    )\b
    \s*(?:=|:)\s*
    (?P<quote>[\"']?)
    (?P<value>[^\n\"'#]+)
    (?P=quote)
    """
)

_IGNORED_VALUES = {
    "",
    "none",
    "null",
    "true",
    "false",
    "0",
}

class EnhancedGenericAssignmentDetector(BaseDetector):
    detector_id = "generic_assignment"
    title = "Generic secret-like assignment"

    def detect(self, fragment: SourceFragment) -> list[Candidate]:
        results: list[Candidate] = []
        lines = fragment.content.splitlines() or [fragment.content]

        for match in ASSIGNMENT_RE.finditer(fragment.content):
            value = match.group("value").strip()
            if not self._is_plausible_secret(value):
                continue

            line_start = fragment.content[: match.start()].count("\n") + 1
            span = fragment.span.model_copy(update={"line_start": line_start, "line_end": line_start})
            line_text = lines[line_start - 1] if 0 < line_start <= len(lines) else match.group(0)

            results.append(
                Candidate(
                    kind=CandidateKind.KEYWORD_VALUE,
                    detector_id=self.detector_id,
                    span=span,
                    match_text=match.group(0),
                    secret_value=value,
                    secret_masked=mask_secret(value),
                    metadata={
                        "provider_known": False,
                        "assignment_key": match.group("key").lower(),
                        "line_text": line_text,
                    },
                    confidence=0.9,
                )
   )

        return results

    @staticmethod
    def _is_plausible_secret(value: str) -> bool:
        lowered = value.strip().lower()
        if lowered in _IGNORED_VALUES:
            return False
        if lowered.startswith(("${", "env(", "os.getenv", "<")):
            return False
        if len(value) < 8:
            return False
        return True