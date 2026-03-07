from __future__ import annotations

from pydantic import BaseModel, Field

from secret_scanner.models.enums import CandidateKind, Severity, ValidationStatus
from secret_scanner.models.source import SourceSpan


class Candidate(BaseModel):
    kind: CandidateKind
    detector_id: str
    span: SourceSpan
    match_text: str
    secret_value: str
    secret_masked: str
    metadata: dict = Field(default_factory=dict)
    confidence: float = 0.0


class Finding(BaseModel):
    id: str
    detector_id: str
    title: str
    description: str
    severity: Severity
    span: SourceSpan
    secret_masked: str
    fingerprint: str
    tags: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
    validation_status: ValidationStatus = ValidationStatus.NOT_RUN
    validation_message: str | None = None
    confidence: float = 0.0
