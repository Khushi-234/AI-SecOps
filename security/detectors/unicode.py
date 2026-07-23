"""
Unicode Detector Module

Detects unicode obfuscation, zero-width characters, homoglyphs,
and other character-level bypass tricks.
"""

from __future__ import annotations

from security.base_detector import DetectorConfig
from security.rule_based_detector import RuleBasedDetector
from security.enums import SeverityLevel, ThreatType

RULE_NAME = "unicode"


class UnicodeDetector(RuleBasedDetector):
    """
    Scans for zero-width characters, invisible symbols, and homoglyphs in user inputs.
    """

    @property
    def detector_name(self) -> str:
        return "UnicodeDetector"

    @property
    def default_threat_type(self) -> ThreatType:
        return ThreatType.UNICODE_OBFUSCATION

    @property
    def default_severity(self) -> SeverityLevel:
        return SeverityLevel.MEDIUM

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__(default_rule_name=RULE_NAME, config=config)
