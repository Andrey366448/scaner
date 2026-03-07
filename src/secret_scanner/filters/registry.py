from __future__ import annotations

from secret_scanner.filters.base import BaseFilter


class FilterRegistry:
    def __init__(self) -> None:
        self._filters: list[BaseFilter] = []

    def register(self, filter_: BaseFilter) -> None:
        self._filters.append(filter_)

    def all(self) -> list[BaseFilter]:
        return list(self._filters)
