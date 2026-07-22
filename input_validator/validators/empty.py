"""
Empty prompt validation check.

Purpose:
    Ensures the incoming query contains actual content and is not empty or whitespace-only.

Responsibilities:
    - Inspect input text and reject None, empty strings, tabs, newlines, or mixed whitespace.
    - Set execution priority to run first in the pipeline sequence.

Validation Rules:
    - Reject: "", " ", "\t", "\n", "\r\n", "\t \n", None (handled at framework level).
    - Accept: Any string with at least one non-whitespace character.

Thread Safety:
    This class is stateless and thread-safe for concurrent evaluations.
"""

from __future__ import annotations

from typing import Any

from input_validator.validators.base_validator import BaseValidator


class EmptyValidator(BaseValidator):
    """Rejects empty, null, or whitespace-only input prompts."""

    @property
    def validator_name(self) -> str:
        """Name of the validator component."""
        return "EmptyValidator"

    @property
    def priority(self) -> int:
        """Pipeline execution priority (lower executes first)."""
        return 10

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        """Validates that the input string is not empty or whitespace-only."""
        if not prompt.strip():
            return False, "Input prompt is empty or contains only whitespace", None

        return True, None, None
