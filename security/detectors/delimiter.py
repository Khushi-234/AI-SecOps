"""
Delimiter Escape Detector Module

Detects delimiter injection attacks (e.g. system tag closures like </system>,
<assistant>, BEGIN PROMPT, END PROMPT) used to escape standard prompt scopes.
"""

from __future__ import annotations

from security.base_detector import DetectorConfig
from security.rule_based_detector import RuleBasedDetector
from security.enums import SeverityLevel, ThreatType


class DelimiterEscapeDetector(RuleBasedDetector):
    """
    Checks for structured tag injections or escape keywords in user prompt structures.
    """

    @property
    def detector_name(self) -> str:
        return "DelimiterEscapeDetector"

    @property
    def default_threat_type(self) -> ThreatType:
        return ThreatType.DELIMITER_ESCAPE

    @property
    def default_severity(self) -> SeverityLevel:
        return SeverityLevel.CRITICAL

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__(default_rule_name="delimiter", config=config)
