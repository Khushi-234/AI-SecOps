"""
Detector for toxic or harmful content in LLM output.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from output_guard.constants import (
    DETECTOR_TOXIC_NAME,
    REGEX_TOXIC_PATTERNS,
    TOXIC_KEYWORDS,
)
from output_guard.detectors.base_detector import BaseOutputDetector
from output_guard.enums import FindingType, OutputSeverity
from output_guard.models import OutputFinding


class ToxicDetector(BaseOutputDetector):
    """
    Scans generated output text for toxic content patterns.
    """

    @property
    def detector_name(self) -> str:
        return DETECTOR_TOXIC_NAME

    def detect(self, output_text: str) -> list[OutputFinding]:
        findings: list[OutputFinding] = []
        if not output_text or not isinstance(output_text, str):
            return findings

        lower_output = output_text.lower()
        matched_keywords = [kw for kw in TOXIC_KEYWORDS if kw in lower_output]

        for pattern in REGEX_TOXIC_PATTERNS:
            matches = pattern.findall(output_text)
            if matches:
                findings.append(
                    OutputFinding(
                        detector_name=self.detector_name,
                        finding_type=FindingType.TOXIC_CONTENT,
                        severity=OutputSeverity.MEDIUM,
                        confidence=self.config.confidence_toxic,
                        matches=tuple(matches),
                        description=f"Detected toxic content pattern ({len(matches)} matches)",
                        metadata={"pattern": pattern.pattern},
                    )
                )

        if matched_keywords and not findings:
            findings.append(
                OutputFinding(
                    detector_name=self.detector_name,
                    finding_type=FindingType.TOXIC_CONTENT,
                    severity=OutputSeverity.MEDIUM,
                    confidence=self.config.confidence_toxic,
                    matches=tuple(matched_keywords),
                    description=f"Detected toxic keywords ({len(matched_keywords)} matches)",
                    metadata={"keywords": matched_keywords},
                )
            )

        return findings


