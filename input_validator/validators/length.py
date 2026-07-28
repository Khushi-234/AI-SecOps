"""
Length validation checker.

Purpose:
    Validates that prompt character length falls within configured boundaries.

Responsibilities:
    - Measure prompt length once.
    - Reject prompts below minimum_length or above maximum_length.
    - Expose priority for ValidationPipeline execution order.

Validation Rules:
    - Reject: len(prompt) < minimum_length or len(prompt) > maximum_length.
    - Return telemetry metadata: character_count, minimum_length, maximum_length, within_limits.

Future Token Validation:
    - Holds a TODO placeholder for tokenizer integrations (e.g., tiktoken, Hugging Face)
      to enforce maximum_tokens.

Thread Safety:
    This class is stateless and thread-safe for concurrent evaluations.
"""

from __future__ import annotations

from typing import Any

from input_validator.base_validator import BaseValidator


class LengthValidator(BaseValidator):
    """Enforces prompt character length constraints."""

    @property
    def validator_name(self) -> str:
        """Name of the validator component."""
        return "LengthValidator"

    @property
    def priority(self) -> int:
        """Pipeline execution priority (lower executes first)."""
        return 20

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        """Checks character length constraints against config limits."""
        min_len = self.config.minimum_length
        max_len = self.config.maximum_length
        char_count = len(prompt)

        # TODO: In Sprint 6.2, replace character-count validation with tokenizer-aware validation
        # (e.g. tiktoken or Hugging Face tokenizers) to enforce maximum_tokens (limit: self.config.maximum_tokens).

        within_limits = min_len <= char_count <= max_len
        metadata = self._build_metadata(char_count, within_limits)

        if char_count < min_len:
            return (
                False,
                f"Input validation failed: prompt length ({char_count} characters) is below "
                f"the configured minimum of {min_len}.",
                metadata,
            )

        if char_count > max_len:
            return (
                False,
                f"Input validation failed: prompt length ({char_count} characters) exceeds "
                f"the configured maximum of {max_len}.",
                metadata,
            )

        return True, None, metadata

    def _build_metadata(self, char_count: int, within_limits: bool) -> dict[str, Any]:
        """Compiles telemetry metadata mapping prompt character bounds and limits."""
        return {
            "character_count": char_count,
            "minimum_length": self.config.minimum_length,
            "maximum_length": self.config.maximum_length,
            "maximum_tokens": self.config.maximum_tokens,
            "within_limits": within_limits,
        }
