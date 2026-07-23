"""
SimpleValidator mixin and base class.

Provides lightweight validation capabilities and helper utilities for simple
rule-based assertions without requiring complex configuration objects.
"""

from __future__ import annotations

from typing import Any
from input_validator.validators.base_validator import BaseValidator


class SimpleValidator(BaseValidator):
    """
    Lightweight Base Validator for single-assertion or rule-based checks.

    Defaults config to None and provides convenient context and data extraction helpers.
    """

    def __init__(self, config: Any = None) -> None:
        """Initializes SimpleValidator with optional configuration."""
        super().__init__(config=config)

    @property
    def validator_name(self) -> str:
        """Default name for SimpleValidator."""
        return "SimpleValidator"

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        """Default validation hook for SimpleValidator (passes by default)."""
        return True, None, None

    def extract_context_data(self, context: dict[str, Any]) -> dict[str, Any]:
        """Safely extracts context dictionary data."""
        if not isinstance(context, dict):
            return {}
        return context

    def get_context_key(
        self, context: dict[str, Any], key: str, default: Any = None
    ) -> Any:
        """Safely retrieves a key from the context payload."""
        if not isinstance(context, dict):
            return default
        return context.get(key, default)
