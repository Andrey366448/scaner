# Импорт класса BaseDetector
from secret_scanner.detectors.base import BaseDetector
from secret_scanner.models import SourceFragment, Candidate, CandidateKind

class EnhancedGenericAssignmentDetector(BaseDetector):
    detector_id = "generic_assignment_detector"  # Добавляем атрибут detector_id
    def detect(self, fragment: SourceFragment):
        candidates = []

        # Пропускаем если ключ содержит известные тестовые значения
        test_keywords = ['test', 'dummy', 'example', 'changeme']
        for key in test_keywords:
            if key in fragment.content.lower():
                return []

        # Логика для обнаружения generic assignment
        if "secret" in fragment.content or "=" in fragment.content:
            candidates.append(
                Candidate(
                    kind=CandidateKind.GENERIC_ASSIGNMENT,
                    detector_id=self.detector_id,
                    span=fragment.span,
                    match_text=fragment.content,
                    secret_value=fragment.content.split('=')[1],
                    secret_masked="***",
                    confidence=0.9
                )
            )

        return candidates