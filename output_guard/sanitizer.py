"""
Output Guard Redaction Engine.

Main pipeline orchestrator for evaluating, inspecting, and sanitizing LLM outputs.
"""

from __future__ import annotations

import logging
from typing import Sequence

from output_guard.config import DEFAULT_OUTPUT_GUARD_CONFIG, OutputGuardConfig
from output_guard.enums import OutputAction
from output_guard.exceptions import InvalidOutputError, OutputGuardError
from output_guard.models import OutputSanitizationResult, SanitizationResult
from output_guard.sanitizers.base_sanitizer import BaseSanitizer
from output_guard.sanitizers.pii_sanitizer import PiiSanitizer
from output_guard.sanitizers.prompt_leak_sanitizer import PromptLeakSanitizer
from output_guard.sanitizers.secret_sanitizer import SecretSanitizer
from output_guard.sanitizers.toxic_sanitizer import ToxicSanitizer
from output_guard.utils import measure_execution_time, truncate_output

logger = logging.getLogger(__name__)


class OutputSanitizer:
    """
    Output Redaction Engine that runs configured sanitizers against LLM generated output.
    """

    def __init__(
        self,
        config: OutputGuardConfig | None = None,
        custom_sanitizers: Sequence[BaseSanitizer] | None = None,
    ) -> None:
        self.config = config or DEFAULT_OUTPUT_GUARD_CONFIG
        self.sanitizers = self._initialize_sanitizers(custom_sanitizers)

    def _initialize_sanitizers(
        self, custom_sanitizers: Sequence[BaseSanitizer] | None
    ) -> list[BaseSanitizer]:
        """Instantiates and orders enabled sanitizers."""
        if custom_sanitizers is not None:
            return list(custom_sanitizers)

        available_sanitizers: list[BaseSanitizer] = [
            SecretSanitizer(self.config),
            PiiSanitizer(self.config),
            PromptLeakSanitizer(self.config),
            ToxicSanitizer(self.config),
        ]

        active_sanitizers = [
            sanitizer
            for sanitizer in available_sanitizers
            if self.config.is_sanitizer_enabled(sanitizer.sanitizer_name)
        ]
        return active_sanitizers

    def sanitize(self, output: str) -> OutputSanitizationResult:
        """
        Sanitizes and inspects LLM generated output.

        Args:
            output: Generated text response from the LLM.

        Returns:
            OutputSanitizationResult containing sanitized text, modified flag,
            applied sanitizers, detected issues, and metadata.
        """
        if output is None:
            if self.config.raise_on_error:
                raise InvalidOutputError("LLM output cannot be None.")
            output = ""

        if not isinstance(output, str):
            if self.config.raise_on_error:
                raise InvalidOutputError(
                    f"LLM output must be a string, got {type(output).__name__}."
                )
            output = str(output)

        with measure_execution_time() as total_elapsed:
            current_output = output

            # Truncate if exceeds max length
            if len(current_output) > self.config.max_output_length and self.config.truncate_exceeding_output:
                current_output = truncate_output(
                    current_output, self.config.max_output_length
                )

            applied_sanitizers: list[str] = []
            detected_issues: list[str] = []
            step_results: list[dict] = []
            is_any_modified = False

            for sanitizer in self.sanitizers:
                try:
                    result: SanitizationResult = sanitizer.sanitize(current_output)
                    step_results.append(result.to_dict())

                    if result.detected_issues:
                        for issue in result.detected_issues:
                            if issue not in detected_issues:
                                detected_issues.append(issue)

                    if result.is_modified:
                        is_any_modified = True
                        applied_sanitizers.append(sanitizer.sanitizer_name)
                        current_output = result.sanitized_output

                except OutputGuardError:
                    if self.config.raise_on_error:
                        raise
                except Exception as e:
                    logger.error(
                        f"Unexpected error running {sanitizer.sanitizer_name}: {e}"
                    )
                    if self.config.raise_on_error:
                        raise OutputGuardError(
                            f"Sanitizer {sanitizer.sanitizer_name} failed: {e}"
                        ) from e

            action = OutputAction.SANITIZE if is_any_modified else OutputAction.ALLOW

        return OutputSanitizationResult(
            original_output=output,
            sanitized_output=current_output,
            modified=is_any_modified,
            applied_sanitizers=applied_sanitizers,
            detected_issues=detected_issues,
            action_taken=action,
            execution_time_ms=total_elapsed(),
            metadata={
                "sanitizers_count": len(self.sanitizers),
                "step_results": step_results,
            },
        )


# Alias for intuitive usage
OutputGuard = OutputSanitizer

__all__ = ["OutputSanitizer", "OutputGuard"]
