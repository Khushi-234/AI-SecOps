"""
Detector for unsafe code payloads or dangerous commands in LLM output.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from output_guard.constants import DETECTOR_UNSAFE_NAME, REGEX_UNSAFE_COMMAND_PATTERNS
from output_guard.detectors.base_detector import BaseOutputDetector
from output_guard.enums import FindingType, OutputSeverity
from output_guard.models import OutputFinding


class UnsafeOutputDetector(BaseOutputDetector):
    """
    Scans generated output text for unsafe commands (e.g. rm -rf, reverse shells, fork bombs).
    """

    @property
    def detector_name(self) -> str:
        return DETECTOR_UNSAFE_NAME

    def detect(self, output_text: str) -> list[OutputFinding]:
        findings: list[OutputFinding] = []
        if not output_text or not isinstance(output_text, str):
            return findings

        for pattern in REGEX_UNSAFE_COMMAND_PATTERNS:
            matches = pattern.findall(output_text)
            if matches:
                findings.append(
                    OutputFinding(
                        detector_name=self.detector_name,
                        finding_type=FindingType.UNSAFE_CODE,
                        severity=OutputSeverity.CRITICAL,
                        confidence=self.config.confidence_unsafe,
                        matches=tuple(matches),
                        description=f"Detected dangerous shell command pattern ({len(matches)} matches)",
                        metadata={"pattern": pattern.pattern, "count": len(matches)},
                    )
                )

        return findings


