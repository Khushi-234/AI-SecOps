"""
Encoding validation check.

Purpose:
    Validates character set encoding integrity and detects corrupt, malformed,
    or dangerous byte/unicode sequences (such as isolated UTF-16 surrogates).

Responsibilities:
    - Inspect prompt string for surrogate pairs or malformed unicode.
    - Inspect byte fields in context for UTF-8 validity.
    - Return telemetry detailing encoding status and identified violations.

Thread Safety:
    Stateless and thread-safe.
"""

from __future__ import annotations

from typing import Any
from input_validator.validators.base_validator import BaseValidator
from input_validator.utils import is_valid_utf8, is_empty


class EncodingValidator(BaseValidator):
    """Validates character encoding integrity for prompts and context payload fields."""

    @property
    def validator_name(self) -> str:
        """Name of the validator component."""
        return "EncodingValidator"

    @property
    def priority(self) -> int:
        """Pipeline execution priority."""
        return 15

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        """Validates UTF-8 encoding integrity and checks for malformed unicode."""
        # 1. Inspect string prompt for surrogate characters (U+D800 to U+DFFF)
        has_surrogates = any(0xD800 <= ord(char) <= 0xDFFF for char in prompt)
        if has_surrogates:
            metadata = {"reason": "isolated_surrogates", "prompt_len": len(prompt)}
            return (
                False,
                "Input validation failed: prompt contains invalid unicode surrogate characters.",
                metadata,
            )

        # 2. Inspect byte objects in context dictionary
        ctx = context or {}
        invalid_byte_keys: list[str] = []
        for key, value in ctx.items():
            if isinstance(value, bytes) and not is_empty(value):
                if not is_valid_utf8(value):
                    invalid_byte_keys.append(key)

        if invalid_byte_keys:
            metadata = {"invalid_byte_keys": invalid_byte_keys}
            return (
                False,
                f"Input validation failed: invalid UTF-8 byte encoding in context keys: {', '.join(invalid_byte_keys)}.",
                metadata,
            )

        metadata = {
            "encoding": "UTF-8",
            "has_surrogates": False,
            "checked_context_byte_keys": len(
                [v for v in ctx.values() if isinstance(v, bytes)]
            ),
        }
        return True, None, metadata
