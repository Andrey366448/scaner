from __future__ import annotations

import re
from urllib.parse import urlsplit

from secret_scanner.detectors.base import BaseDetector
from secret_scanner.models import Candidate, CandidateKind, SourceFragment
from secret_scanner.utils.strings import mask_secret

URI_RE = re.compile(r"\b(?P<uri>[A-Za-z][A-Za-z0-9+.-]{1,20}://[^\s'\"<>]+)")
SUPPORTED_SCHEMES = {
    "http",
    "https",
    "postgres",
    "postgresql",
    "mysql",
    "redis",
    "mongodb",
    "amqp",
    "ftp",
    "sftp",
}


class UriCredentialsDetector(BaseDetector):
    detector_id = "uri_credentials"
    title = "URI with embedded credentials"

    def detect(self, fragment: SourceFragment) -> list[Candidate]:
        results: list[Candidate] = []
        lines = fragment.content.splitlines() or [fragment.content]
        for match in URI_RE.finditer(fragment.content):
            uri = match.group("uri").rstrip(".,);]")
            try:
                parsed = urlsplit(uri)
            except ValueError:
                continue
            if parsed.scheme.lower() not in SUPPORTED_SCHEMES:
                continue
            if parsed.username is None or parsed.password is None:
                continue
            password = parsed.password or ""
            if not password:
                continue
            line_start = fragment.content[: match.start()].count("\n") + 1
            span = fragment.span.model_copy(update={"line_start": line_start, "line_end": line_start})
            line_text = lines[line_start - 1] if 0 < line_start <= len(lines) else uri
            masked_uri = uri.replace(password, mask_secret(password))
            results.append(
                Candidate(
                    kind=CandidateKind.STRUCTURAL,
                    detector_id=self.detector_id,
                    span=span,
                    match_text=uri,
                    secret_value=password,
                    secret_masked=masked_uri,
                    metadata={
                        "provider_known": False,
                        "uri_scheme": parsed.scheme.lower(),
                        "uri_username": parsed.username,
                        "embedded_credentials": True,
                        "line_text": line_text,
                    },
                    confidence=1.05,
                )
            )
        return results
