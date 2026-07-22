"""
Completeness validation checker.

Purpose:
    Ensures that mandatory request parameters and payload context fields are present
    and contain non-empty, non-null values.

Responsibilities:
    - Inspect request dictionary for required fields.
    - Reject payloads missing critical attributes (such as user prompt, request_id, timestamp).
    - Expose priority for pipeline orchestration.
"""

from __future__ import annotations

from typing import Any
from input_validator.validators.base_validator import BaseValidator
from input_validator.utils import is_empty

DEFAULT_REQUIRED_FIELDS = {"user", "request_id"}


class CompletenessValidator(BaseValidator):
    """Ensures required top-level payload attributes and context parameters are present and non-empty."""

    @property
    def validator_name(self) -> str:
        """Name of the validator component."""
        return "CompletenessValidator"

    @property
    def priority(self) -> int:
        """Pipeline execution priority."""
        return 65
        

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        """Validates that all required attributes are present and non-empty."""
        ctx = context or {}
        required = getattr(self.config, "required_fields", DEFAULT_REQUIRED_FIELDS) if self.config else DEFAULT_REQUIRED_FIELDS
        required_set = set(required) if isinstance(required, (list, set, tuple)) else set(required.keys()) if isinstance(required, dict) else DEFAULT_REQUIRED_FIELDS

        missing_fields: list[str] = []

        # Check prompt string first if 'user' or 'prompt' is required
        if "user" in required_set and (not prompt or is_empty(prompt)):
            missing_fields.append("user")

        # Check remaining required keys in context payload
        for field in required_set:
            if field == "user":
                continue
            if field not in ctx or is_empty(ctx.get(field)):
                missing_fields.append(field)

        metadata = {
            "required_fields": list(required_set),
            "missing_fields": missing_fields,
            "is_complete": len(missing_fields) == 0,
        }

        if missing_fields:
            return (
                False,
                f"Input validation failed: missing or empty required fields: {', '.join(missing_fields)}.",
                metadata,
            )

        return True, None, metadata