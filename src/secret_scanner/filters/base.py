from __future__ import annotations

from abc import ABC, abstractmethod

from pydantic import BaseModel

from secret_scanner.models import Candidate, SourceFragment


class FilterDecision(BaseModel):
    suppressed: bool
    reason: str | None = None


class BaseFilter(ABC):
    filter_id: str

    @abstractmethod
    def apply(self, candidate: Candidate, fragment: SourceFragment) -> FilterDecision:
        raise NotImplementedError
