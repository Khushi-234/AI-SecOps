"""
Sanitizer for detecting and neutralizing unsafe command payloads in LLM output.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from output_guard.constants import REGEX_UNSAFE_COMMAND_PATTERNS, SANITIZER_UNSAFE_OUTPUT_NAME, UNSAFE_KEYWORDS
from output_guard.enums import SanitizationType
from output_guard.exceptions import SanitizationError
from output_guard.models import SanitizationResult
from output_guard.sanitizers.base_sanitizer import BaseSanitizer
from output_guard.utils import measure_execution_time

logger = logging.getLogger(__name__)


class UnsafeOutputSanitizer(BaseSanitizer):
    """
    Scans generated LLM output for dangerous shell commands (e.g. rm -rf, curl|sh, reverse shells)
    and redacts unsafe command snippets with replacement tokens.
    """

    @property
    def sanitizer_name(self) -> str:
        return SANITIZER_UNSAFE_OUTPUT_NAME

    @property
    def sanitization_type(self) -> SanitizationType:
        return SanitizationType.UNSAFE_CODE


    def sanitize(self, output: str) -> SanitizationResult:
        """
        Sanitizes dangerous shell commands and unsafe code snippets.
        """
        if not output or not isinstance(output, str):
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
            replacement_token = getattr(self.config, "unsafe_output_replacement", "[REDACTED_UNSAFE_COMMAND]")
            replacements_count = 0

            try:
                for pattern in REGEX_UNSAFE_COMMAND_PATTERNS:
                    current_text, count = pattern.subn(replacement_token, current_text)
                    if count > 0:
                        replacements_count += count
                        issue_desc = f"Unsafe command pattern match ({count} occurrences)"
                        if issue_desc not in detected_issues:
                            detected_issues.append(issue_desc)
                        changes.append(
                            {
                                "pattern": pattern.pattern,
                                "count": count,
                                "replacement": replacement_token,
                            }
                        )

                # Redact plain keyword matches (case-insensitive) in single pass
                for keyword in UNSAFE_KEYWORDS:
                    current_text, count = re.subn(
                        re.escape(keyword), replacement_token, current_text, flags=re.IGNORECASE
                    )
                    if count > 0:
                        replacements_count += count
                        issue_desc = f"Unsafe keyword match: '{keyword}'"
                        if issue_desc not in detected_issues:
                            detected_issues.append(issue_desc)
                        changes.append(
                            {
                                "keyword": keyword,
                                "count": count,
                                "replacement": replacement_token,
                            }
                        )

            except Exception as e:
                logger.error(f"Error in UnsafeOutputSanitizer execution: {e}")
                if self.config.raise_on_error:
                    raise SanitizationError(
                        f"UnsafeOutputSanitizer failed: {str(e)}",
                        sanitizer_name=self.sanitizer_name,
                    ) from e

            is_modified = (current_text != output)
            exec_time = elapsed()

        return SanitizationResult(
            sanitizer_name=self.sanitizer_name,
            sanitization_type=self.sanitization_type,
            is_modified=is_modified,
            original_output=output,
            sanitized_output=current_text,
            changes=changes,
            detected_issues=detected_issues,
            execution_time_ms=exec_time,
            metadata={"replacements_count": replacements_count},
        )


__all__ = ["UnsafeOutputSanitizer"]
