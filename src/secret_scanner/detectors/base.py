from __future__ import annotations

from abc import ABC, abstractmethod

from secret_scanner.models import Candidate, SourceFragment


class BaseDetector(ABC):
    detector_id: str
    title: str

    @abstractmethod
    def detect(self, fragment: SourceFragment) -> list[Candidate]:
        raise NotImplementedError
