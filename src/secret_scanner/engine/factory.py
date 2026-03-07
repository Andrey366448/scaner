from __future__ import annotations

from secret_scanner.baseline import BaselineStore
from secret_scanner.collectors.filesystem import FilesystemCollector
from secret_scanner.collectors.git_diff import GitDiffCollector
from secret_scanner.collectors.git_staged import GitStagedCollector
from secret_scanner.config.models import AppConfig
from secret_scanner.detectors.builtins.generic_assignment import GenericAssignmentDetector
from secret_scanner.detectors.builtins.private_key import PrivateKeyDetector
from secret_scanner.engine.scanner import Scanner
from secret_scanner.filters.baseline_filter import BaselineFilter
from secret_scanner.filters.dummy_value_filter import DummyValueFilter
from secret_scanner.filters.path_filter import PathFilter


def build_scanner(
    paths: list[str],
    config: AppConfig,
    *,
    staged: bool = False,
    git_diff: str | None = None,
    use_baseline: bool | None = None,
) -> Scanner:
    collector = _build_collector(paths=paths, config=config, staged=staged, git_diff=git_diff)

    detectors = []
    enabled = set(config.detectors.enabled)
    if "private_key" in enabled:
        detectors.append(PrivateKeyDetector())
    if "generic_assignment" in enabled:
        detectors.append(GenericAssignmentDetector())

    filters = [
        PathFilter(ignore_paths=config.filters.ignore_paths),
        DummyValueFilter(dummy_values=config.filters.dummy_values),
    ]

    baseline_enabled = config.baseline.use_baseline if use_baseline is None else use_baseline
    if baseline_enabled:
        store = BaselineStore(config.baseline.path)
        fingerprints = store.load_fingerprints()
        if fingerprints:
            filters.append(BaselineFilter(fingerprints=fingerprints))

    return Scanner(
        collector=collector,
        detectors=detectors,
        filters=filters,
    )


def _build_collector(
    paths: list[str],
    config: AppConfig,
    *,
    staged: bool,
    git_diff: str | None,
):
    if staged:
        return GitStagedCollector(config=config)
    if git_diff is not None:
        return GitDiffCollector(refspec=git_diff, config=config)
    return FilesystemCollector(paths=paths, config=config)
