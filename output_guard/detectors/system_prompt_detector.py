"""
Detector for system prompt leaks and internal directive disclosures in LLM output.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from output_guard.constants import (
    DETECTOR_PROMPT_LEAK_NAME,
    PROMPT_LEAK_PHRASES,
    REGEX_PROMPT_LEAK_PATTERNS,
)
from output_guard.detectors.base_detector import BaseOutputDetector
from output_guard.enums import FindingType, OutputSeverity
from output_guard.models import OutputFinding


class SystemPromptDetector(BaseOutputDetector):
    """
    Scans LLM output text for system prompt leaks and internal instructions.
    """

    @property
    def detector_name(self) -> str:
        return DETECTOR_PROMPT_LEAK_NAME

    def detect(self, output_text: str) -> list[OutputFinding]:
        findings: list[OutputFinding] = []
        if not output_text or not isinstance(output_text, str):
            return findings

        lower_output = output_text.lower()
        matched_phrases = [p for p in PROMPT_LEAK_PHRASES if p in lower_output]

        if matched_phrases:
            findings.append(
                OutputFinding(
                    detector_name=self.detector_name,
                    finding_type=FindingType.PROMPT_LEAK,
                    severity=OutputSeverity.HIGH,
                    confidence=self.config.confidence_prompt_leak,
                    matches=tuple(matched_phrases),
                    description=f"Detected prompt leak phrase ({len(matched_phrases)} matches)",
                    metadata={"matched_phrases": matched_phrases},
                )
            )

        for pattern in REGEX_PROMPT_LEAK_PATTERNS:
            matches = pattern.findall(output_text)
            if matches:
                findings.append(
                    OutputFinding(
                        detector_name=self.detector_name,
                        finding_type=FindingType.PROMPT_LEAK,
                        severity=OutputSeverity.HIGH,
                        confidence=self.config.confidence_prompt_leak,
                        matches=tuple(matches),
                        description=f"Detected prompt leak regex pattern ({len(matches)} matches)",
                        metadata={"pattern": pattern.pattern},
                    )
                )

        return findings


