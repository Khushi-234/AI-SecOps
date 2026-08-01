"""
Sanitizer for detecting and modifying toxic, abusive, or unsafe content in LLM output.
"""

from __future__ import annotations

import logging
from typing import Any

from output_guard.constants import (
    REGEX_TOXIC_PATTERNS,
    SANITIZER_TOXIC_NAME,
    TOXIC_KEYWORDS,
)
from output_guard.enums import SanitizationType
from output_guard.exceptions import SanitizationError
from output_guard.models import SanitizationResult
from output_guard.sanitizers.base_sanitizer import BaseSanitizer
from output_guard.utils import measure_execution_time, replace_regex_matches

logger = logging.getLogger(__name__)


class ToxicSanitizer(BaseSanitizer):
    """
    Detects toxic, harmful, abusive, or unsafe text in LLM responses and sanitizes or replaces it.
    """

    @property
    def sanitizer_name(self) -> str:
        return SANITIZER_TOXIC_NAME

    @property
    def sanitization_type(self) -> SanitizationType:
        return SanitizationType.TOXIC_CONTENT

    def sanitize(self, output: str) -> SanitizationResult:
        """
        Scans output for toxic patterns and keywords and replaces them with safe alternatives or tokens.
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

            replacement_token = self.config.toxic_replacement

            try:
                # Scan for regex patterns
                for pattern in REGEX_TOXIC_PATTERNS:
                    for match in pattern.finditer(current_text):
                        issue_msg = "Detected toxic content pattern"
                        if issue_msg not in detected_issues:
                            detected_issues.append(issue_msg)

                    new_text, count = replace_regex_matches(
                        current_text, pattern, replacement_token
                    )
                    if count > 0:
                        total_replacements += count
                        changes.append(
                            {
                                "type": "toxic_pattern",
                                "count": count,
                                "replacement": replacement_token,
                            }
                        )
                        current_text = new_text

                # Scan for keywords
                lower_text = current_text.lower()
                for keyword in TOXIC_KEYWORDS:
                    if keyword in lower_text:
                        issue_msg = f"Detected toxic keyword: '{keyword}'"
                        if issue_msg not in detected_issues:
                            detected_issues.append(issue_msg)

            except Exception as e:
                logger.error(f"Error in ToxicSanitizer execution: {e}")
                if self.config.raise_on_error:
                    raise SanitizationError(
                        f"ToxicSanitizer failed: {str(e)}",
                        sanitizer_name=self.sanitizer_name,
                    ) from e

            is_modified = total_replacements > 0 or len(detected_issues) > 0

            # If toxic content was detected but not fully replaced by regex, apply replacement token
            if is_modified and current_text == output:
                current_text = replacement_token
                changes.append(
                    {
                        "type": "toxic_content_replaced",
                        "replacement": replacement_token,
                    }
                )

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


__all__ = ["ToxicSanitizer"]
