from __future__ import annotations

from secret_scanner.baseline import fingerprint_candidate
from secret_scanner.collectors import BaseCollector
from secret_scanner.detectors import BaseDetector
from secret_scanner.engine.severity import SeverityScorer
from secret_scanner.filters import BaseFilter
from secret_scanner.models import Candidate, Finding, ScanResult, ScanStats


class Scanner:
    def __init__(
        self,
        collector: BaseCollector,
        detectors: list[BaseDetector],
        filters: list[BaseFilter],
    ) -> None:
        self.collector = collector
        self.detectors = detectors
        self.filters = filters
        self.severity_scorer = SeverityScorer()

    def run(self) -> ScanResult:
        fragments = self.collector.collect()
        stats = ScanStats(
            files_seen=len(fragments),
            files_scanned=len(fragments),
            fragments_scanned=len(fragments),
        )
        findings: list[Finding] = []

        for fragment in fragments:
            for detector in self.detectors:
                candidates = detector.detect(fragment)
                stats.candidates_found += len(candidates)
                for candidate in candidates:
                    if self._is_suppressed(candidate, fragment):
                        stats.findings_suppressed += 1
                        continue
                    findings.append(self._build_finding(candidate))

        findings = self._deduplicate(findings)
        stats.findings_reported = len(findings)
        return ScanResult(findings=findings, stats=stats)

    def _is_suppressed(self, candidate: Candidate, fragment) -> bool:
        for filter_ in self.filters:
            decision = filter_.apply(candidate, fragment)
            if decision.suppressed:
                return True
        return False

    def _build_finding(self, candidate: Candidate) -> Finding:
        severity, confidence = self.severity_scorer.score(candidate)
        fingerprint = fingerprint_candidate(candidate)
        finding_id = fingerprint[:12]
        title = candidate.detector_id.replace("_", " ").title()
        description = f"Potential secret found by detector '{candidate.detector_id}'."
        tags = [candidate.detector_id]
        if candidate.metadata.get("provider_known"):
            tags.append("provider-specific")
        return Finding(
            id=finding_id,
            detector_id=candidate.detector_id,
            title=title,
            description=description,
            severity=severity,
            span=candidate.span,
            secret_masked=candidate.secret_masked,
            fingerprint=fingerprint,
            metadata=candidate.metadata,
            tags=tags,
            confidence=confidence,
        )

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        unique: dict[str, Finding] = {}
        for finding in findings:
            unique[finding.fingerprint] = finding
        return list(unique.values())
