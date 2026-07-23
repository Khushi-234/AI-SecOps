from enum import Enum


class SeverityLevel(str, Enum):
    """
    Classification levels for threat severity rating within the framework.

    Used to indicate the severity of a security violation flagged by a detector.
    Inherits from str to ensure easy JSON and database serialization.
    """

    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionStatus(str, Enum):
    """
    Execution outcome status of a single detector run.

    Used to trace pipeline health, trace timeouts, or capture errors
    occurring within individual detector modules.
    """

    SUCCESS = "SUCCESS"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


class ThreatType(str, Enum):
    """
    Standard classification of security vulnerabilities handled by the framework.

    These represent the targeted threat types evaluated by prompt detectors.
    """

    NONE = "NONE"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    SECRET_EXTRACTION = "SECRET_EXTRACTION"
    UNICODE_OBFUSCATION = "UNICODE_OBFUSCATION"
    DELIMITER_ESCAPE = "DELIMITER_ESCAPE"
    TOOL_ABUSE = "TOOL_ABUSE"
