"""
Secret Extraction Detector Module

Detects queries attempting to extract sensitive credentials, passwords, 
API keys, system environment variables, or private tokens.
"""

from __future__ import annotations

from security.base_detector import DetectorConfig
from security.rule_based_detector import RuleBasedDetector
from security.enums import SeverityLevel, ThreatType

class SecretExtractionDetector(RuleBasedDetector):
    """
    Checks for attempts to read or steal keys, passwords, tokens, or environment variables.
    """

    @property
    def detector_name(self) -> str:
        return "SecretExtractionDetector"

    @property
    def default_threat_type(self) -> ThreatType:
        return ThreatType.SECRET_EXTRACTION

    @property
    def default_severity(self) -> SeverityLevel:
        return SeverityLevel.HIGH

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__(default_rule_name="secret", config=config)
