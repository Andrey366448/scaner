from __future__ import annotations

import re
from math import log2
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

_IGNORED_VALUES = {"", "none", "null", "true", "false", "0"}

_PLACEHOLDER_HINTS = {
    "example",
    "sample",
    "placeholder",
    "dummy",
    "fake",
    "mock",
    "changeme",
    "todo",
    "foobar",
}

_KNOWN_SECRET_PREFIXES = (
    "ghp_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "sk_live_",
    "sk_test_",
    "eyJ",
)


class EnhancedGenericAssignmentDetector(BaseDetector):
    detector_id = "generic_assignment"
    title = "Generic secret-like assignment"

    def detect(self, fragment: SourceFragment) -> list[Candidate]:
        results: list[Candidate] = []
        lines = fragment.content.splitlines() or [fragment.content]

        for match in ASSIGNMENT_RE.finditer(fragment.content):
            value = match.group("value").strip()
            key = match.group("key").lower()
            quote = match.group("quote")
            if not self._is_plausible_secret(key, value):
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
                        "certain_secret": value.strip().startswith(_KNOWN_SECRET_PREFIXES),
                        "explicit_literal": bool(quote),
                        "assignment_key": key,
                        "entropy": self._shannon_entropy(value),
                        "line_text": line_text,
                    },
                    confidence=0.9,
                )
            )

        return results

    def _is_plausible_secret(self, key: str, value: str) -> bool:
        stripped = value.strip()
        lowered = stripped.lower()

        if lowered in _IGNORED_VALUES:
            return False
        if lowered.startswith(("${", "env(", "os.getenv", "<")):
            return False
        if lowered.startswith(("http://", "https://", "file://", "./", "../", "/")):
            return False
        if any(hint in lowered for hint in _PLACEHOLDER_HINTS):
            return False
        if len(stripped) < 8:
            return False

        if stripped.startswith(_KNOWN_SECRET_PREFIXES):
            return True

        entropy = self._shannon_entropy(stripped)
        has_digit = any(char.isdigit() for char in stripped)
        has_upper = any(char.isupper() for char in stripped)
        has_symbol = any(not char.isalnum() for char in stripped)

        if entropy >= 3.6 and len(stripped) >= 12:
            return True

        key_is_high_risk = key in {"api_key", "access_token", "refresh_token", "client_secret"}
        if key_is_high_risk and len(stripped) >= 12 and (has_digit or has_symbol or has_upper):
            return True

        if len(stripped) >= 20 and has_digit and (has_upper or has_symbol):
            return True

        return False

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        counts: dict[str, int] = {}
        for char in value:
            counts[char] = counts.get(char, 0) + 1
        length = len(value)
        return -sum((count / length) * log2(count / length) for count in counts.values())
