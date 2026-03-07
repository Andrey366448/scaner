from __future__ import annotations
try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib
from pathlib import Path
from typing import Any

from secret_scanner.config.defaults import DEFAULT_CONFIG_FILENAMES
from secret_scanner.config.models import AppConfig


def _extract_pyproject_tool_config(data: dict[str, Any]) -> dict[str, Any]:
    return data.get("tool", {}).get("secret-scanner", {})


def _load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    if path.name == "pyproject.toml":
        return _extract_pyproject_tool_config(data)
    return data


def find_default_config(start_dir: Path | None = None) -> Path | None:
    start = (start_dir or Path.cwd()).resolve()
    for directory in [start, *start.parents]:
        for filename in DEFAULT_CONFIG_FILENAMES:
            candidate = directory / filename
            if candidate.exists() and candidate.is_file():
