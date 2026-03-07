from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import json
from pydantic import BaseModel, Field

from secret_scanner.models import Finding


class BaselineEntry(BaseModel):
    fingerprint: str
    detector_id: str
    path: str
    line_start: int
    severity: str


class BaselineFile(BaseModel):
    version: int = 1
    generated_at: str
    findings: list[BaselineEntry] = Field(default_factory=list)


class BaselineStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def exists(self) -> bool:
        return self.path.exists() and self.path.is_file()

    def load_fingerprints(self) -> set[str]:
        if not self.exists():
            return set()
        with self.path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        baseline = BaselineFile.model_validate(data)
        return {entry.fingerprint for entry in baseline.findings}

    def write_findings(self, findings: list[Finding]) -> None:
        entries = [
            BaselineEntry(
                fingerprint=finding.fingerprint,
                detector_id=finding.detector_id,
                path=finding.span.path,
                line_start=finding.span.line_start,
                severity=finding.severity.value,
            )
            for finding in findings
        ]
        baseline = BaselineFile(
            generated_at=datetime.now(timezone.utc).isoformat(),
            findings=entries,
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as fh:
            json.dump(baseline.model_dump(), fh, indent=2, ensure_ascii=False)
            fh.write("\n")
