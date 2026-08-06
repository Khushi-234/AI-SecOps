"""
Sanitizer for redacting Personally Identifiable Information (PII) from LLM output.
"""

from __future__ import annotations

import logging
from typing import Any, Sequence

from output_guard.constants import SANITIZER_PII_NAME
from output_guard.enums import FindingType, SanitizationType
from output_guard.exceptions import SanitizationError
from output_guard.models import OutputFinding, SanitizationResult
from output_guard.sanitizers.base_sanitizer import BaseSanitizer
from output_guard.utils import measure_execution_time

logger = logging.getLogger(__name__)


class PiiSanitizer(BaseSanitizer):
    """
    Sanitizes PII (emails, phone numbers, IP addresses, SSN, credit cards)
    from LLM generated responses by consuming OutputFinding objects from PiiDetector.
    Does not run independent regex pattern detection.
    """

    @property
    def sanitizer_name(self) -> str:
        return SANITIZER_PII_NAME

    @property
    def sanitization_type(self) -> SanitizationType:
        return SanitizationType.PII

    def _get_replacement_for_type(self, pii_type: str) -> str:
        """Helper to get specific or fallback replacement token."""
        mapping = {
            "email": self.config.email_replacement,
            "phone": self.config.phone_replacement,
            "ipv4": self.config.ip_replacement,
            "ipv6": self.config.ip_replacement,
            "ssn": self.config.ssn_replacement,
            "credit_card": self.config.credit_card_replacement,
        }
        return mapping.get(pii_type, self.config.pii_replacement)

    def _get_replacement_for_finding(self, finding: OutputFinding) -> str:
        """Helper to get replacement token based on finding metadata pii_category."""
        pii_category = finding.metadata.get("pii_category") if finding.metadata else None
        return self._get_replacement_for_type(str(pii_category) if pii_category is not None else "")

    def sanitize(
        self,
        output: str,
        findings: Sequence[OutputFinding] | None = None,
    ) -> SanitizationResult:
        """
        Redacts detected PII values from output text using provided findings.
        """
        if not output:
            return SanitizationResult(
                sanitizer_name=self.sanitizer_name,
                sanitization_type=self.sanitization_type,
                is_modified=False,
                original_output=output or "",
                sanitized_output=output or "",
                changes=[],
                detected_issues=[],
                execution_time_ms=0.0,
            )

        with measure_execution_time() as elapsed:
            current_text = output
            changes: list[dict[str, Any]] = []
            detected_issues: list[str] = []
            total_replacements = 0

            if findings:
                try:
                    for finding in findings:
                        if getattr(finding, "finding_type", None) != FindingType.PII:
                            continue

                        pii_category = (
                            finding.metadata.get("pii_category", "unknown")
                            if finding.metadata
                            else "unknown"
                        )
                        replacement_token = self._get_replacement_for_finding(finding)
                        matches = getattr(finding, "matches", ()) or ()
                        finding_count = 0

                        for match in matches:
                            if match and match in current_text:
                                match_occurrences = current_text.count(match)
                                if match_occurrences > 0:
                                    current_text = current_text.replace(match, replacement_token)
                                    finding_count += match_occurrences

                        if finding_count > 0:
                            total_replacements += finding_count
                            issue_msg = f"Detected PII ({pii_category})"
                            if issue_msg not in detected_issues:
                                detected_issues.append(issue_msg)
                            changes.append(
                                {
                                    "pii_type": pii_category,
                                    "count": finding_count,
                                    "replacement": replacement_token,
                                }
                            )

                except Exception as e:
                    logger.error(f"Error in PiiSanitizer execution: {e}")
                    if self.config.raise_on_error:
                        raise SanitizationError(
                            f"PiiSanitizer failed: {str(e)}",
                            sanitizer_name=self.sanitizer_name,
                        ) from e

            is_modified = total_replacements > 0

        return SanitizationResult(
            sanitizer_name=self.sanitizer_name,
            sanitization_type=self.sanitization_type,
            is_modified=is_modified,
            original_output=output,
            sanitized_output=current_text,
            changes=changes,
            detected_issues=detected_issues,
            execution_time_ms=elapsed(),
            metadata={"replacements_count": total_replacements},
        )


__all__ = ["PiiSanitizer"]
