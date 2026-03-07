from __future__ import annotations

import re

from secret_scanner.detectors.regex_detector import RegexDetector
from secret_scanner.models import SourceFragment


class PrivateKeyDetector(RegexDetector):
    detector_id = "private_key"
    title = "Private key"
    patterns = [
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            re.DOTALL,
        )
    ]

    def base_confidence(self, match: re.Match[str], fragment: SourceFragment) -> float:
        return 1.5

    def build_metadata(self, match: re.Match[str], fragment: SourceFragment) -> dict:
        return {"category": "private_key", "provider_known": False}
