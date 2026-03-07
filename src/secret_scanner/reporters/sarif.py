from __future__ import annotations

import json

from secret_scanner.models import Finding, ScanResult

LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


class SarifReporter:
    def render(self, result: ScanResult) -> str:
        rules = {}
        sarif_results = []
        for finding in sorted(result.findings, key=lambda item: (item.span.path, item.span.line_start, item.detector_id)):
            rules.setdefault(
                finding.detector_id,
                {
                    "id": finding.detector_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "properties": {"tags": finding.tags or ["security", "secret"]},
                },
            )
            sarif_results.append(self._result_for_finding(finding))

        payload = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "secret-scanner",
                            "informationUri": "https://example.invalid/secret-scanner",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)

    @staticmethod
    def _result_for_finding(finding: Finding) -> dict:
        line_text = str(finding.metadata.get("line_text", "")).strip()
        message = f"{finding.title}: {finding.secret_masked}"
        if line_text:
            message = f"{message} in `{line_text}`"
        return {
            "ruleId": finding.detector_id,
            "level": LEVEL_MAP[finding.severity.value],
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.span.path},
                        "region": {
                            "startLine": finding.span.line_start,
                            "endLine": finding.span.line_end,
                        },
                    }
                }
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": finding.fingerprint,
            },
            "properties": {
                "severity": finding.severity.value,
                "confidence": round(finding.confidence, 3),
            },
        }
