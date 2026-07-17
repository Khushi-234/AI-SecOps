"""
Encoding Detector Module

Detects encoded payloads such as Base64, Hex, URL Encoding, ROT13, etc.,
designed to bypass string-matching security layers.
"""

from __future__ import annotations

from security.base_detector import DetectorConfig
from security.rule_based_detector import RuleBasedDetector
from security.enums import SeverityLevel, ThreatType


class EncodingDetector(RuleBasedDetector):
    """
    Scans for heavily encoded or obfuscated text patterns (Base64, Hex, URL encoding).
    """

    @property
    def detector_name(self) -> str:
        return "EncodingDetector"

    @property
    def default_threat_type(self) -> ThreatType:
        return ThreatType.PROMPT_INJECTION

    @property
    def default_severity(self) -> SeverityLevel:
        return SeverityLevel.HIGH

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__(default_rule_name="encoding", config=config)
