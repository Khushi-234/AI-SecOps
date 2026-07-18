"""
Prompt Injection Detector Module

Detects direct prompt injection attacks aiming to override system prompts or 
force arbitrary response control.
"""

from __future__ import annotations

from security.base_detector import DetectorConfig
from security.rule_based_detector import RuleBasedDetector
from security.enums import SeverityLevel, ThreatType

class PromptInjectionDetector(RuleBasedDetector):
    """
    Checks for instructions designed to bypass or ignore context boundaries and instructions.
    """
    @property
    def detector_name(self) -> str:
        return "prompt_injection_detector"

    @property
    def default_threat_type(self) -> ThreatType:
        return ThreatType.PROMPT_INJECTION

    @property
    def default_severity(self) -> SeverityLevel:
        return SeverityLevel.HIGH

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__(default_rule_name="prompt_injection", config=config)
