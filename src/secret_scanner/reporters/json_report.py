from __future__ import annotations

import json

from secret_scanner.models import ScanResult


class JsonReporter:
    def render(self, result: ScanResult) -> str:
        return json.dumps(result.model_dump(mode="json"), indent=2, ensure_ascii=False)
