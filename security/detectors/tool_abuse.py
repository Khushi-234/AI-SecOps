"""
Tool Abuse Detector Module

Detects queries attempting to abuse external tools or execute unauthorized code 
(e.g., shell command execution, file deletion, arbitrary python code execution).
"""

from __future__ import annotations

from security.base_detector import DetectorConfig
from security.rule_based_detector import RuleBasedDetector
from security.enums import SeverityLevel, ThreatType


class ToolAbuseDetector(RuleBasedDetector):
    """
    Checks for commands, execution syntax, or scripting patterns indicating tool exploit attempts.
    """

    @property
    def detector_name(self) -> str:
        return "ToolAbuseDetector"

    @property
    def default_threat_type(self) -> ThreatType:
        return ThreatType.TOOL_ABUSE

    @property
    def default_severity(self) -> SeverityLevel:
        return SeverityLevel.CRITICAL

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__(default_rule_name="tool_abuse", config=config)