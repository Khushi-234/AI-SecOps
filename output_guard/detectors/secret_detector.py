"""
Detector for credentials and API keys in LLM output.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from output_guard.constants import (
    DEFAULT_CONFIDENCE_SECRET,
    DEFAULT_SEVERITY_SECRET,
    DETECTOR_SECRET_NAME,
    SECRET_PATTERNS,
)
from output_guard.detectors.base_detector import BaseOutputDetector
from output_guard.models import OutputFinding


class SecretDetector(BaseOutputDetector):
    """
    Scans generated output text for API keys, access tokens, and secrets.
    """

    @property
    def detector_name(self) -> str:
        return DETECTOR_SECRET_NAME

    def detect(self, output_text: str) -> list[OutputFinding]:
        findings: list[OutputFinding] = []
        if not output_text or not isinstance(output_text, str):
            return findings

        for secret_type, pattern in SECRET_PATTERNS.items():
            matches = pattern.findall(output_text)
            if matches:
                match_strings = [m[0] if isinstance(m, tuple) else m for m in matches]
                findings.append(
                    OutputFinding(
                        detector_name=self.detector_name,
                        finding_type="SECRET",
                        severity=DEFAULT_SEVERITY_SECRET,
                        confidence=DEFAULT_CONFIDENCE_SECRET,
                        matches=tuple(match_strings),
                        description=f"Detected secret category '{secret_type}' ({len(matches)} matches)",
                        metadata={"secret_category": secret_type, "count": len(matches)},
                    )
                )
        return findings

