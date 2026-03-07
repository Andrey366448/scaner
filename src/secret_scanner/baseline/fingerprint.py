from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from secret_scanner.models import Candidate


def _normalize_path(path: str) -> str:
    return Path(path).as_posix().lower()


def _normalize_secret(value: str) -> str:
    return value.strip()


def fingerprint_candidate(candidate: Candidate) -> str:
    payload = "|".join(
        [
            candidate.detector_id,
            _normalize_path(candidate.span.path),
            _normalize_secret(candidate.secret_value),
        ]
    )
    return sha256(payload.encode("utf-8")).hexdigest()
