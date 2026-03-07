from __future__ import annotations

from secret_scanner.models import ScanResult


class TextReporter:
    def render(self, result: ScanResult) -> str:
        if not result.findings:
            return "No findings."

        lines: list[str] = []
        for finding in sorted(result.findings, key=lambda item: (item.span.path, item.span.line_start)):
            lines.append(f"[{finding.severity.value.upper()}] {finding.title}")
            lines.append(f"  file: {finding.span.path}:{finding.span.line_start}")
            lines.append(f"  detector: {finding.detector_id}")
            lines.append(f"  secret: {finding.secret_masked}")
            lines.append(f"  confidence: {finding.confidence:.2f}")
            lines.append("")
        return "\n".join(lines).rstrip()
