"""
Sanitizer for detecting and preventing system prompt disclosure or internal instruction leaks in LLM output.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from output_guard.constants import (
    DEFAULT_PROMPT_LEAK_RESPONSE,
    PROMPT_LEAK_PHRASES,
    REGEX_PROMPT_LEAK_PATTERNS,
    SANITIZER_PROMPT_LEAK_NAME,
)
from output_guard.enums import SanitizationType
from output_guard.exceptions import SanitizationError
from output_guard.models import SanitizationResult
from output_guard.sanitizers.base_sanitizer import BaseSanitizer
from output_guard.utils import measure_execution_time

logger = logging.getLogger(__name__)


class PromptLeakSanitizer(BaseSanitizer):
    """
    Detects and sanitizes responses where the LLM attempts to reveal system prompts,
    developer instructions, internal policies, or hidden rules.
    Supports configurable prompt leak modes: MASK, REMOVE, REPLACE, BLOCK.
    """

    @property
    def sanitizer_name(self) -> str:
        return SANITIZER_PROMPT_LEAK_NAME

    @property
    def sanitization_type(self) -> SanitizationType:
        return SanitizationType.PROMPT_LEAK

    def sanitize(self, output: str) -> SanitizationResult:
        """
        Scans output for prompt leakage indicators and sanitizes text based on configured mode.
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

            try:
                lower_output = output.lower()

                # Check static phrases
                for phrase in PROMPT_LEAK_PHRASES:
                    if phrase in lower_output:
                        is_leak_detected = True
                        issue_msg = f"Detected prompt leak phrase: '{phrase}'"
                        if issue_msg not in detected_issues:
                            detected_issues.append(issue_msg)

                # Check regex patterns
                for pattern in REGEX_PROMPT_LEAK_PATTERNS:
                    matches = pattern.findall(current_text)
                    if matches:
                        is_leak_detected = True
                        issue_msg = "Detected prompt leak pattern match"
                        if issue_msg not in detected_issues:
                            detected_issues.append(issue_msg)

                if is_leak_detected:
                    if mode == "BLOCK":
                        sanitized = DEFAULT_PROMPT_LEAK_RESPONSE
                    elif mode == "REMOVE":
                        sanitized = current_text
                        for phrase in PROMPT_LEAK_PHRASES:
                            pattern = re.compile(re.escape(phrase), re.IGNORECASE)
                            sanitized = pattern.sub("", sanitized)
                        for pattern in REGEX_PROMPT_LEAK_PATTERNS:
                            sanitized = pattern.sub("", sanitized)
                    elif mode == "REPLACE":
                        sanitized = DEFAULT_PROMPT_LEAK_RESPONSE
                    else:  # MASK (default)
                        stripped_lower = lower_output.strip()
                        if any(stripped_lower.startswith(p) for p in PROMPT_LEAK_PHRASES) or len(output.split()) < 40:
                            sanitized = DEFAULT_PROMPT_LEAK_RESPONSE
                        else:
                            sanitized = current_text
                            for phrase in PROMPT_LEAK_PHRASES:
                                pattern = re.compile(re.escape(phrase), re.IGNORECASE)
                                sanitized = pattern.sub(replacement_token, sanitized)
                            for pattern in REGEX_PROMPT_LEAK_PATTERNS:
                                sanitized = pattern.sub(replacement_token, sanitized)

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

            # audit_logger.info(
            #     "[OutputGuard Audit] Sanitizer: %s | Mode: %s | Modified: %s | Time: %.2fms",
            #     self.sanitizer_name,
            #     mode,
            #     is_modified,
            #     exec_time,
            # )

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
