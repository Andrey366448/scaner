from __future__ import annotations
from collections import Counter
from secret_scanner.models import ScanResult


class TextReporter:
    def render(self, result: ScanResult) -> str:
        if not result.findings:
            return "No findings."

        lines: list[str] = []
        by_severity = Counter(f.severity.value for f in result.findings)
        lines.append("Findings summary:")
        for severity in ("critical", "high", "medium", "low", "info"):
            count = by_severity.get(severity, 0)
            if count:
                lines.append(f"  - {severity}: {count}")
        lines.append("")

        for finding in sorted(result.findings, key=lambda item: (item.span.path, item.span.line_start)):
            lines.append(f"[{finding.severity.value.upper()}] {finding.title}")
            lines.append(f"  file: {finding.span.path}:{finding.span.line_start}")
            lines.append(f"  detector: {finding.detector_id}")
            lines.append(f"  secret: {finding.secret_masked}")
            line_text = str(finding.metadata.get("line_text", "")).strip()
            if line_text:
                lines.append(f"  line: {line_text[:220]}")
            lines.append(f"  confidence: {finding.confidence:.2f}")
            lines.append("")
            lines.append("Hint: use --format json for machine-readable output.")
        return "\n".join(lines).rstrip()
