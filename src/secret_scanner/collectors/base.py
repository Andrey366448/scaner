from __future__ import annotations

from abc import ABC, abstractmethod

from secret_scanner.models import SourceFragment


class BaseCollector(ABC):
    @abstractmethod
    def collect(self) -> list[SourceFragment]:
        raise NotImplementedError
