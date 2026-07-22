"""
Format validation checker.

Purpose:
    Validates structural formatting of specific prompt fields or context inputs
    against standard patterns (e.g. Email, UUID, URL, JSON).

Responsibilities:
    - Evaluate field format patterns cleanly using regex shortcuts.
    - Provide clear format failure reasons without exposing raw regex internals.
"""

from __future__ import annotations

import json
from typing import Any
from input_validator.validators.base_validator import BaseValidator
from input_validator.utils import matches_regex, is_empty

DEFAULT_FORMAT_RULES = {
    "email": r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$",
    "uuid": r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    "url": r"^https?://[^\s/$.?#].[^\s]*$",
}


class FormatValidator(BaseValidator):
    """Validates structural formats (email, UUID, URL, JSON) for context or prompt payloads."""

    @property
    def validator_name(self) -> str:
        """Name of the validator component."""
        return "FormatValidator"

    @property
    def priority(self) -> int:
        """Pipeline execution priority."""
        return 35

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        """Validates that structured parameters match expected regular expressions or format contracts."""
        ctx = context or {}
        mismatches: list[str] = []
        checked_fields: list[str] = []

        # Check configured format rules against context fields
        rules = getattr(self.config, "format_rules", DEFAULT_FORMAT_RULES) if self.config else DEFAULT_FORMAT_RULES

        for field_name, pattern in rules.items():
            if field_name in ctx:
                val = ctx[field_name]
                if val is None or is_empty(val):
                    continue
                checked_fields.append(field_name)
                if not isinstance(val, str) or not matches_regex(pattern, val):
                    mismatches.append(field_name)

        # Optional JSON payload format verification
        if ctx.get("expected_format") == "json":
            try:
                json.loads(prompt)
            except (ValueError, TypeError):
                mismatches.append("prompt_json")

        metadata = {
            "checked_fields": checked_fields,
            "mismatch_count": len(mismatches),
            "mismatched_fields": mismatches,
        }

        if mismatches:
            return (
                False,
                f"Input validation failed: format mismatches found in fields: {', '.join(mismatches)}.",
                metadata,
            )

        return True, None, metadata