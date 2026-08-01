"""
Sanitizer Pipeline orchestration component.
Runs enabled sanitizers in precise sequence: Injection -> Secret -> PII.
"""

from __future__ import annotations

from typing import Sequence

from prompt_hardener.config import HardenerConfig, DEFAULT_HARDENER_CONFIG
from prompt_hardener.enums import SanitizationType
from prompt_hardener.exceptions import SanitizationError
from prompt_hardener.models import SanitizationResult
from prompt_hardener.sanitizers.base import BaseSanitizer
from prompt_hardener.sanitizers.injection_sanitizer import InjectionSanitizer
from prompt_hardener.sanitizers.secret_sanitizer import SecretSanitizer
from prompt_hardener.sanitizers.pii_sanitizer import PiiSanitizer


class SanitizerPipeline:
    """
    Sequentially executes enabled sanitizers on input prompts.
    """

    def __init__(
        self,
        config: HardenerConfig | None = None,
        sanitizers: Sequence[BaseSanitizer] | None = None,
    ) -> None:
        self.config = config or DEFAULT_HARDENER_CONFIG

        if sanitizers is not None:
            self.sanitizers = list(sanitizers)
        else:
            # Default pipeline order: Injection -> Secret -> PII
            self.sanitizers = [
                InjectionSanitizer(self.config),
                SecretSanitizer(self.config),
                PiiSanitizer(self.config),
            ]

    def run(self, prompt: str) -> SanitizationResult:
        """
        Runs the prompt through all configured sanitizers in sequence.

        Args:
            prompt: Raw prompt text to sanitize.

        Returns:
            SanitizationResult containing the fully sanitized text and metadata.
        """
        if not prompt or not isinstance(prompt, str):
            return SanitizationResult(
                original_text=prompt or "",
                sanitized_text=prompt or "",
                sanitizer_type="PIPELINE",
                modified=False,
                replacements_count=0,
            )

        current_text = prompt
        applied: list[str] = []
        total_replacements = 0
        step_results: dict[str, dict] = {}

        for sanitizer in self.sanitizers:
            # Skip sanitizer if disabled in configuration
            sanitizer_name = sanitizer.sanitizer_type.value.lower()
            if (
                self.config.enabled_sanitizers
                and sanitizer_name not in self.config.enabled_sanitizers
            ):
                continue

            try:
                res = sanitizer.sanitize(current_text)
                if res.modified:
                    applied.append(res.sanitizer_type)
                    current_text = res.sanitized_text
                    total_replacements += res.replacements_count
                step_results[res.sanitizer_type] = res.to_dict()
            except Exception as exc:
                if self.config.raise_on_error:
                    raise SanitizationError(
                        f"Sanitizer '{sanitizer.__class__.__name__}' failed: {exc}",
                        details={"sanitizer": sanitizer.__class__.__name__},
                    ) from exc

        return SanitizationResult(
            original_text=prompt,
            sanitized_text=current_text,
            sanitizer_type="PIPELINE",
            modified=(current_text != prompt),
            replacements_count=total_replacements,
            metadata={
                "applied_sanitizers": applied,
                "step_results": step_results,
            },
        )


__all__ = ["SanitizerPipeline"]
