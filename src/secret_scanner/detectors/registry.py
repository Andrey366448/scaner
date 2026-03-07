from __future__ import annotations

from secret_scanner.detectors.base import BaseDetector


class DetectorRegistry:
    def __init__(self) -> None:
        self._detectors: list[BaseDetector] = []

    def register(self, detector: BaseDetector) -> None:
        self._detectors.append(detector)

    def all(self) -> list[BaseDetector]:
        return list(self._detectors)
