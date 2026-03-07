import json  # Импортируем модуль json
from secret_scanner.reporters.base import BaseReporter
class SarifReporter(BaseReporter):
    def render(self, result):
        sarif_report = {
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {"name": "secret-scan", "version": "1.0.0"}
                },
                "results": [{
                    "ruleId": finding.detector_id,
                    "message": {"text": finding.title},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.span.path},
                            "region": {"startLine": finding.span.line_start}
                        }
                    }]
                } for finding in result.findings]
            }]
        }

        return json.dumps(sarif_report, indent=2)  # Используем json для сериализации