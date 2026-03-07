from __future__ import annotations

import base64
import json
import re

from secret_scanner.detectors.base import BaseDetector
from secret_scanner.models import Candidate, CandidateKind, SourceFragment
from secret_scanner.utils.strings import mask_secret

JWT_RE = re.compile(r"\b(?P<token>[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b")


class JwtDetector(BaseDetector):
    detector_id = "jwt"
    title = "JSON Web Token"

    def detect(self, fragment: SourceFragment) -> list[Candidate]:
        results: list[Candidate] = []
        lines = fragment.content.splitlines() or [fragment.content]
        for match in JWT_RE.finditer(fragment.content):
            token = match.group("token")
            header, payload, _signature = token.split(".", 2)
            decoded_header = self._decode_json_segment(header)
            decoded_payload = self._decode_json_segment(payload)
            if decoded_header is None or decoded_payload is None:
                continue
            if not decoded_header.get("alg"):
                continue
            if not isinstance(decoded_payload, dict):
                continue

            line_start = fragment.content[: match.start()].count("\n") + 1
            span = fragment.span.model_copy(update={"line_start": line_start, "line_end": line_start})
            line_text = lines[line_start - 1] if 0 < line_start <= len(lines) else token
            results.append(
                Candidate(
                    kind=CandidateKind.STRUCTURAL,
                    detector_id=self.detector_id,
                    span=span,
                    match_text=token,
                    secret_value=token,
                    secret_masked=mask_secret(token),
                    metadata={
                        "provider_known": False,
                        "certain_secret": True,
                        "jwt_alg": decoded_header.get("alg"),
                        "jwt_typ": decoded_header.get("typ"),
                        "jwt_claim_keys": sorted(decoded_payload.keys())[:10],
                        "line_text": line_text,
                    },
                    confidence=1.1,
                )
            )
        return results

    @staticmethod
    def _decode_json_segment(segment: str) -> dict | None:
        padding = "=" * ((4 - len(segment) % 4) % 4)
        try:
            decoded = base64.urlsafe_b64decode((segment + padding).encode("ascii"))
            data = json.loads(decoded.decode("utf-8"))
        except Exception:
            return None
        return data if isinstance(data, dict) else None
