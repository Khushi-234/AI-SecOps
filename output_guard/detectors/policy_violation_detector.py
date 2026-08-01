"""
Detector for security policy violations in LLM output.
"""

from __future__ import annotations

from typing import Any, Mapping

from output_guard.constants import DETECTOR_POLICY_VIOLATION_NAME
from output_guard.detectors.base_detector import BaseOutputDetector
from output_guard.enums import FindingType, OutputSeverity
from output_guard.models import OutputFinding


class PolicyViolationDetector(BaseOutputDetector):
    """
    Detects organizational policy violations present in generated output text.
    """

    @property
    def detector_name(self) -> str:
        return DETECTOR_POLICY_VIOLATION_NAME

    def detect(self, output_text: str) -> list[OutputFinding]:
        findings: list[OutputFinding] = []
        if not output_text or not isinstance(output_text, str):
            return findings

        if "[UNAUTHORIZED]" in output_text or "[POLICY_VIOLATION]" in output_text:
            findings.append(
                OutputFinding(
                    detector_name=self.detector_name,
                    finding_type=FindingType.POLICY_VIOLATION,
                    severity=OutputSeverity.HIGH,
                    confidence=self.config.confidence_policy_violation,
                    matches=("[UNAUTHORIZED]",),
                    description="Detected policy violation tag in output text",
                    metadata={"count": 1},
                )
            )
        return findings


