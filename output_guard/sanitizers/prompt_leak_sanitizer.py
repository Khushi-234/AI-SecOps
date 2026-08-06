"""
Sanitizer for preventing system prompt disclosure or internal instruction leaks in LLM output.
"""

from __future__ import annotations

import logging
from typing import Any, Sequence

from output_guard.constants import (
    DEFAULT_PROMPT_LEAK_RESPONSE,
    SANITIZER_PROMPT_LEAK_NAME,
)
from output_guard.enums import FindingType, SanitizationType
from output_guard.exceptions import SanitizationError
from output_guard.models import OutputFinding, SanitizationResult
from output_guard.sanitizers.base_sanitizer import BaseSanitizer
from output_guard.utils import measure_execution_time

logger = logging.getLogger(__name__)


class PromptLeakSanitizer(BaseSanitizer):
    """
    Sanitizes responses where system prompt leaks or internal instructions are detected
    by consuming OutputFinding objects from SystemPromptDetector.
    Supports configurable prompt leak modes: MASK, REMOVE, REPLACE, BLOCK.
    Does not run independent pattern detection.
    """

    @property
    def sanitizer_name(self) -> str:
        return SANITIZER_PROMPT_LEAK_NAME

    @property
    def sanitization_type(self) -> SanitizationType:
        return SanitizationType.PROMPT_LEAK

    def _get_replacement_for_finding(self, finding: OutputFinding) -> str:
        """Helper to get replacement token for prompt leak findings."""
        return self.config.prompt_leak_replacement

    def sanitize(
        self,
        output: str,
        findings: Sequence[OutputFinding] | None = None,
    ) -> SanitizationResult:
        """
        Sanitizes output text containing detected prompt leaks using provided findings.
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
            is_leak_detected = False

            replacement_token = self.config.prompt_leak_replacement
            mode = getattr(self.config, "prompt_leak_mode", "MASK").upper()

            if findings:
                try:
                    for finding in findings:
                        if getattr(finding, "finding_type", None) != FindingType.PROMPT_LEAK:
                            continue

                        is_leak_detected = True
                        issue_msg = getattr(finding, "description", None) or "Detected prompt leak"
                        if issue_msg not in detected_issues:
                            detected_issues.append(issue_msg)

                        matches = getattr(finding, "matches", ()) or ()
                        if mode == "BLOCK" or mode == "REPLACE":
                            sanitized = DEFAULT_PROMPT_LEAK_RESPONSE
                        elif mode == "REMOVE":
                            sanitized = current_text
                            for match in matches:
                                if match and match in sanitized:
                                    sanitized = sanitized.replace(match, "")
                        else:  # MASK (default)
                            if len(output.split()) < 40 or not matches:
                                sanitized = DEFAULT_PROMPT_LEAK_RESPONSE
                            else:
                                sanitized = current_text
                                for match in matches:
                                    if match and match in sanitized:
                                        sanitized = sanitized.replace(match, replacement_token)

                        changes.append(
                            {
                                "leak_detected": True,
                                "mode": mode,
                                "replacement": replacement_token,
                                "sanitized_output": sanitized,
                            }
                        )
                        current_text = sanitized

                except Exception as e:
                    logger.error(f"Error in PromptLeakSanitizer execution: {e}")
                    if self.config.raise_on_error:
                        raise SanitizationError(
                            f"PromptLeakSanitizer failed: {str(e)}",
                            sanitizer_name=self.sanitizer_name,
                        ) from e

            is_modified = is_leak_detected
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
            metadata={"leak_detected": is_leak_detected, "mode": mode},
        )


__all__ = ["PromptLeakSanitizer"]
