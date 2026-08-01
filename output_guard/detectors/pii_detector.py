"""
Detector for PII disclosure in LLM output.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from output_guard.constants import DETECTOR_PII_NAME, PII_PATTERNS
from output_guard.detectors.base_detector import BaseOutputDetector
from output_guard.enums import FindingType, OutputSeverity
from output_guard.models import OutputFinding


class PiiDetector(BaseOutputDetector):
    """
    Scans generated output text for PII elements like email, phone, SSN, and credit cards.
    """

    @property
    def detector_name(self) -> str:
        return DETECTOR_PII_NAME

    def detect(self, output_text: str) -> list[OutputFinding]:
        findings: list[OutputFinding] = []
        if not output_text or not isinstance(output_text, str):
            return findings

        severity_map = {
            "email": OutputSeverity.MEDIUM,
            "phone": OutputSeverity.MEDIUM,
            "ssn": OutputSeverity.CRITICAL,
            "credit_card": OutputSeverity.CRITICAL,
        }

        for pii_type, pattern in PII_PATTERNS.items():
            matches = pattern.findall(output_text)
            if matches:
                findings.append(
                    OutputFinding(
                        detector_name=self.detector_name,
                        finding_type=FindingType.PII,
                        severity=severity_map.get(pii_type, OutputSeverity.MEDIUM),
                        confidence=self.config.confidence_pii,
                        matches=tuple(matches),
                        description=f"Detected PII category '{pii_type}' ({len(matches)} matches)",
                        metadata={"pii_category": pii_type, "count": len(matches)},
                    )
                )

        return findings


