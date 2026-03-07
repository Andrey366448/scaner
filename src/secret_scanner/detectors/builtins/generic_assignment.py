import logging
from secret_scanner.models import Candidate, CandidateKind  # Добавьте этот импорт
from secret_scanner.detectors.base import BaseDetector  # Добавьте этот импорт
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

class EnhancedGenericAssignmentDetector(BaseDetector):
    detector_id = "generic_assignment_detector"

    def detect(self, fragment: SourceFragment):
        candidates = []
        logger.debug(f"Processing fragment: {fragment.content}")

        # Пропускаем если ключ содержит известные тестовые значения
        test_keywords = ['test', 'dummy', 'example', 'changeme']
        for key in test_keywords:
            if key in fragment.content.lower():
                return []

        # Логика для обнаружения generic assignment
        if "secret" in fragment.content or "=" in fragment.content:
            try:
                secret_value = fragment.content.split('=')[1]  # Может быть причиной ошибки
                candidates.append(
                    Candidate(
                        kind=CandidateKind.GENERIC_ASSIGNMENT,
                        detector_id=self.detector_id,
                        span=fragment.span,
                        match_text=fragment.content,
                        secret_value=secret_value,
                        secret_masked="***",
                        confidence=0.9
                    )
                )
                logger.debug(f"Secret detected: {secret_value}")
            except IndexError as e:
                logger.error(f"Error processing fragment: {fragment.content}, {e}")
        
        return candidates