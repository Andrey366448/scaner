# src/secret_scanner/reporters/base.py

from abc import ABC, abstractmethod

class BaseReporter(ABC):
    @abstractmethod
    def render(self, result):
        """Метод для рендеринга отчета."""
        pass