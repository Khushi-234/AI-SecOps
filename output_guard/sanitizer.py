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
from output_guard.sanitizers.pipeline import SanitizationPipeline
from output_guard.sanitizers.prompt_leak_sanitizer import PromptLeakSanitizer
from output_guard.sanitizers.secret_sanitizer import SecretSanitizer
from output_guard.sanitizers.toxic_sanitizer import ToxicSanitizer
from output_guard.sanitizers.unsafe_output_sanitizer import UnsafeOutputSanitizer
from output_guard.utils import measure_execution_time, truncate_output

logger = logging.getLogger(__name__)


class OutputSanitizer:
    """
    Output Redaction Engine that runs configured sanitizers against LLM generated output via SanitizationPipeline.
    """

    def __init__(
        self,
        config: OutputGuardConfig | None = None,
        custom_sanitizers: Sequence[BaseSanitizer] | None = None,
    ) -> None:
        self.config = config or DEFAULT_OUTPUT_GUARD_CONFIG
        self.pipeline = SanitizationPipeline(self.config, sanitizers=custom_sanitizers)

    def sanitize(self, output: str) -> OutputSanitizationResult:
        """
        Delegates sanitization execution to SanitizationPipeline.
        """
        return self.pipeline.run(output)


# Alias for intuitive usage
OutputGuard = OutputSanitizer

__all__ = ["OutputSanitizer", "OutputGuard"]
