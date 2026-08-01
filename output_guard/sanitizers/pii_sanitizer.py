"""
Sanitizer for detecting and redacting Personally Identifiable Information (PII) from LLM output.
"""

from __future__ import annotations

import logging
from typing import Any

from output_guard.constants import PII_PATTERNS, SANITIZER_PII_NAME
from output_guard.enums import SanitizationType
from output_guard.exceptions import SanitizationError
from output_guard.models import SanitizationResult
from output_guard.sanitizers.base_sanitizer import BaseSanitizer
from output_guard.utils import measure_execution_time, replace_regex_matches

logger = logging.getLogger(__name__)


class PiiSanitizer(BaseSanitizer):
    """
    Detects and sanitizes PII (emails, phone numbers, IP addresses, SSN, credit cards)
    from LLM generated responses.
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

    def sanitize(self, output: str) -> SanitizationResult:
        """
        Scans output for PII patterns and replaces them with replacement tokens.
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

            try:
                for pii_type, pattern in PII_PATTERNS.items():
                    replacement_token = self._get_replacement_for_type(pii_type)

                    for match in pattern.finditer(current_text):
                        issue_msg = f"Detected PII ({pii_type})"
                        if issue_msg not in detected_issues:
                            detected_issues.append(issue_msg)

                    new_text, count = replace_regex_matches(
                        current_text, pattern, replacement_token
                    )
                    if count > 0:
                        total_replacements += count
                        changes.append(
                            {
                                "pii_type": pii_type,
                                "count": count,
                                "replacement": replacement_token,
                            }
                        )
                        current_text = new_text

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
