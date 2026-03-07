from __future__ import annotations

from pydantic import BaseModel, Field

from secret_scanner.models.finding import Finding


class ScanStats(BaseModel):
    files_seen: int = 0
    files_scanned: int = 0
    fragments_scanned: int = 0
    candidates_found: int = 0
    findings_reported: int = 0
    findings_suppressed: int = 0


class ScanResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    stats: ScanStats = Field(default_factory=ScanStats)
    errors: list[str] = Field(default_factory=list)
