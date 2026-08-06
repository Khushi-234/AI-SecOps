"""
Sanitizer for detecting and redacting sensitive credentials and secrets from LLM output.
"""

from __future__ import annotations

import logging
from typing import Any

from output_guard.constants import SANITIZER_SECRET_NAME, SECRET_PATTERNS
from output_guard.enums import SanitizationType
from output_guard.exceptions import SanitizationError
from output_guard.models import SanitizationResult
from output_guard.sanitizers.base_sanitizer import BaseSanitizer
from output_guard.utils import measure_execution_time, replace_regex_matches

logger = logging.getLogger(__name__)


class SecretSanitizer(BaseSanitizer):
    """
    Detects and sanitizes sensitive secrets (API keys, tokens, passwords, credentials, private keys)
    from LLM generated responses.
    """

    @property
    def sanitizer_name(self) -> str:
        return SANITIZER_SECRET_NAME

    @property
    def sanitization_type(self) -> SanitizationType:
        return SanitizationType.SECRET

    def sanitize(self, output: str) -> SanitizationResult:
        """
        Scans output for secret leak patterns and replaces them with replacement tokens.
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

            replacement_token = self.config.secret_replacement

            try:
                for secret_type, pattern in SECRET_PATTERNS.items():
                    new_text, count = replace_regex_matches(
                        current_text, pattern, replacement_token
                    )
                    if count > 0:
                        total_replacements += count
                        issue_msg = f"Detected secret ({secret_type})"
                        if issue_msg not in detected_issues:
                            detected_issues.append(issue_msg)
                        changes.append(
                            {
                                "secret_type": secret_type,
                                "count": count,
                                "replacement": replacement_token,
                            }
                        )
                        current_text = new_text

            except Exception as e:
                logger.error(f"Error in SecretSanitizer execution: {e}")
                if self.config.raise_on_error:
                    raise SanitizationError(
                        f"SecretSanitizer failed: {str(e)}",
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


__all__ = ["SecretSanitizer"]
