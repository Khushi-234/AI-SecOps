"""
Sanitization Pipeline Orchestrator.

Sequentially chains prompt sanitizers to apply clean, auditable prompt transformations.
"""

from __future__ import annotations

import time
from typing import Sequence

from policy_engine.config import SanitizationConfig
from policy_engine.context import RiskContext
from policy_engine.models import SanitizationEdit, SanitizationResult
from policy_engine.sanitizers.base import BaseSanitizer
from policy_engine.sanitizers.injection_sanitizer import InjectionSanitizer
from policy_engine.sanitizers.pii_sanitizer import PIISanitizer
from policy_engine.sanitizers.secret_sanitizer import SecretSanitizer


class SanitizationPipeline:
    """
    Executes an ordered pipeline of sanitizers against an input prompt and RiskContext.
    """

    def __init__(
        self,
        sanitizers: Sequence[BaseSanitizer] | None = None,
        config: SanitizationConfig | None = None,
    ) -> None:
        """Initializes pipeline with given sanitizers or creates default sequence from config."""
        self._config = config or SanitizationConfig()
        if sanitizers is not None:
            self._sanitizers: list[BaseSanitizer] = list(sanitizers)
        else:
            self._sanitizers = []
            if self._config.enable_injection_stripping:
                self._sanitizers.append(InjectionSanitizer())
            if self._config.enable_pii_sanitization:
                self._sanitizers.append(
                    PIISanitizer(placeholder=self._config.pii_placeholder)
                )
            if self._config.enable_secret_masking:
                self._sanitizers.append(
                    SecretSanitizer(placeholder=self._config.secret_placeholder)
                )

    def execute(
        self, prompt: str, context: RiskContext | None = None
    ) -> SanitizationResult:
        """
        Executes all active sanitizers sequentially.
        """
        start_time = time.perf_counter()
        current_prompt = prompt
        accumulated_edits: list[SanitizationEdit] = []

        for sanitizer in self._sanitizers:
            res = sanitizer.sanitize(current_prompt, context=context)
            current_prompt = res.sanitized_prompt
            accumulated_edits.extend(res.edits)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return SanitizationResult(
            sanitized_prompt=current_prompt,
            edits=tuple(accumulated_edits),
            processing_time_ms=elapsed_ms,
        )
