"""
Output Guard Facade Public API interface.
"""

from __future__ import annotations

from typing import Any, Sequence

from output_guard.config import DEFAULT_OUTPUT_GUARD_CONFIG, OutputGuardConfig
from output_guard.detectors import BaseOutputDetector
from output_guard.engine import OutputGuardEngine
from output_guard.models import OutputSanitizationResult
from output_guard.sanitizer import OutputSanitizer


class OutputGuardFacade:
    """
    Public API Facade for inspecting, sanitizing, and validating LLM output responses.
    """

    def __init__(
        self,
        config: OutputGuardConfig | None = None,
        sanitizer: OutputSanitizer | None = None,
        detectors: Sequence[BaseOutputDetector] | None = None,
    ) -> None:
        self.config = config or DEFAULT_OUTPUT_GUARD_CONFIG
        self.engine = OutputGuardEngine(
            config=self.config,
            sanitizer=sanitizer,
            detectors=detectors,
        )

    def guard_output(self, llm_output: str) -> OutputSanitizationResult:
        """
        Guards LLM output response against safety violations, secrets, PII, and leaks.

        Args:
            llm_output: Raw generated output text from LLM.

        Returns:
            OutputSanitizationResult DTO containing sanitized text, action taken, and metadata.
        """
        return self.engine.process(llm_output)


def get_output_guard(config: OutputGuardConfig | None = None) -> OutputGuardFacade:
    """Factory helper to obtain instantiated OutputGuardFacade."""
    return OutputGuardFacade(config=config)


__all__ = ["OutputGuardFacade", "get_output_guard"]
