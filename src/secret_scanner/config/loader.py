from __future__ import annotations

import tomllib
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
                return candidate
    return None


def load_config(config_path: str | None = None) -> AppConfig:
    if config_path is None:
        found = find_default_config()
        if found is None:
            return AppConfig()
        return AppConfig.model_validate(_load_toml(found))

    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    return AppConfig.model_validate(_load_toml(path))
