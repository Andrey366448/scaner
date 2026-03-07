from __future__ import annotations

from pydantic import BaseModel, Field


class ScanConfig(BaseModel):
    max_file_size_kb: int = 512
    follow_symlinks: bool = False
    workers: int = 4


class OutputConfig(BaseModel):
    format: str = "text"
    show_snippet: bool = True
    mask_secrets: bool = True


class SeverityConfig(BaseModel):
    fail_on: list[str] = Field(default_factory=lambda: ["high", "critical"])


class BaselineConfig(BaseModel):
    path: str = ".secrets.baseline.json"
    use_baseline: bool = True


class FiltersConfig(BaseModel):
    ignore_paths: list[str] = Field(default_factory=list)
    dummy_values: list[str] = Field(
        default_factory=lambda: [
            "test",
            "dummy",
            "example",
            "changeme",
            "your_api_key_here",
            "xxx",
        ]
    )


class DetectorsConfig(BaseModel):
    enabled: list[str] = Field(
        default_factory=lambda: ["private_key", "generic_assignment"]
    )


class AppConfig(BaseModel):
    scan: ScanConfig = Field(default_factory=ScanConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    severity: SeverityConfig = Field(default_factory=SeverityConfig)
    baseline: BaselineConfig = Field(default_factory=BaselineConfig)
    filters: FiltersConfig = Field(default_factory=FiltersConfig)
    detectors: DetectorsConfig = Field(default_factory=DetectorsConfig)
