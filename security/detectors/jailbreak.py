"""
Jailbreak Detector Module

Detects LLM jailbreak attempts including Persona Adoption (e.g. DAN, Developer Mode),
Evil Prompts, Refusal Suppression, hypothetical scenario bypasses, and prefix injections.
"""

from __future__ import annotations

from security.base_detector import DetectorConfig
from security.rule_based_detector import RuleBasedDetector
from security.enums import SeverityLevel, ThreatType


class JailbreakDetector(RuleBasedDetector):
    """
    Scans prompts for known jailbreak attacks, structural bypasses, and roleplay tricks.

    Execution Pipeline:
    -------------------
    1. Validation: Verifies if detector is active in configs. If disabled, skips analysis.
    2. Input Extraction: Resolves tracking metrics and context request_id parameters.
    3. Regex matching: Iterates over precompiled pattern match rules.
    4. Keyword matching: Scans prompt word-tokens against rules-defined keyword lists.
    5. Phrase matching: Checks substring containment against rules-defined trigger phrases.
    6. Aggregation: Collects all matched instances across rules.
    7. Priority selection: Selects the highest priority rule (lowest number) using min().
    8. DTO compilation: Packages findings into a standard DetectionResult object.
    """

    @property
    def detector_name(self) -> str:
        return "JailbreakDetector"

    @property
    def default_threat_type(self) -> ThreatType:
        return ThreatType.JAILBREAK

    @property
    def default_severity(self) -> SeverityLevel:
        return SeverityLevel.CRITICAL

    def __init__(self, config: DetectorConfig | None = None) -> None:
        """
        Initializes the detector, locating and loading the rule configuration.

        Args:
            config: Configurations defining custom thresholds or file overrides.
        """
        super().__init__(default_rule_name="jailbreak", config=config)
