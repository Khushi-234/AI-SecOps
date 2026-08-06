"""
Sanitizer for neutralizing unsafe command payloads in LLM output.
"""

from __future__ import annotations

import logging
from typing import Any, Sequence

from output_guard.constants import SANITIZER_UNSAFE_OUTPUT_NAME
from output_guard.enums import FindingType, SanitizationType
from output_guard.exceptions import SanitizationError
from output_guard.models import OutputFinding, SanitizationResult
from output_guard.sanitizers.base_sanitizer import BaseSanitizer
from output_guard.utils import measure_execution_time

logger = logging.getLogger(__name__)


class UnsafeOutputSanitizer(BaseSanitizer):
    """
    Sanitizes dangerous shell commands (e.g. rm -rf, curl|sh, reverse shells)
    from LLM generated output by consuming OutputFinding objects from UnsafeOutputDetector.
    Does not run independent pattern detection.
    """

    @property
    def sanitizer_name(self) -> str:
        return SANITIZER_UNSAFE_OUTPUT_NAME

    @property
    def sanitization_type(self) -> SanitizationType:
        return SanitizationType.UNSAFE_CODE

    def _get_replacement_for_finding(self, finding: OutputFinding) -> str:
        """Helper to get replacement token for unsafe command findings."""
        return getattr(self.config, "unsafe_output_replacement", "[REDACTED_UNSAFE_COMMAND]")

    def sanitize(
        self,
        output: str,
        findings: Sequence[OutputFinding] | None = None,
    ) -> SanitizationResult:
        """
        Sanitizes dangerous shell commands and unsafe code snippets using provided findings.
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
            replacements_count = 0

            if findings:
                try:
                    for finding in findings:
                        if getattr(finding, "finding_type", None) != FindingType.UNSAFE_CODE:
                            continue

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
                            replacements_count += finding_count
                            issue_desc = f"Unsafe command pattern match ({finding_count} occurrences)"
                            if issue_desc not in detected_issues:
                                detected_issues.append(issue_desc)
                            changes.append(
                                {
                                    "count": finding_count,
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
