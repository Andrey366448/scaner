from __future__ import annotations

from secret_scanner.models import Candidate, Severity


class SeverityScorer:
    def score(self, candidate: Candidate) -> tuple[Severity, float]:
        score = candidate.confidence
        entropy = float(candidate.metadata.get("entropy", 0.0))
        if entropy >= 4.0:
            score += 0.2
        if candidate.detector_id == "private_key":
            score += 0.8
        if bool(candidate.metadata.get("provider_known")):
            score += 0.4
        if score >= 1.7:
            return Severity.CRITICAL, score
        if score >= 1.2:
            return Severity.HIGH, score
        if score >= 0.8:
            return Severity.MEDIUM, score
        if score >= 0.5:
            return Severity.LOW, score
        return Severity.INFO, score
