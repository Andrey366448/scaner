from enum import Enum


class CandidateKind(str, Enum):
    REGEX = "regex"
    KEYWORD_VALUE = "keyword_value"
    STRUCTURAL = "structural"
    DECODED = "decoded"
    GENERIC_ASSIGNMENT = "generic_assignment"

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ValidationStatus(str, Enum):
    NOT_RUN = "not_run"
    VALID = "valid"
    INVALID = "invalid"
    ERROR = "error"
    UNSUPPORTED = "unsupported"
