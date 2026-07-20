# completeness.py
"""Validator that ensures the input contains all required fields.

The ``REQUIRED_FIELDS`` set defines keys that must be present and non‑empty.
If any are missing or empty, the validator fails. This is a simple complement
to ``SchemaValidator`` which also checks types.
"""

from .base_validator import BaseValidator
from ..models import ValidationResult
from ..utils import is_empty

# Define required fields for the overall payload.
REQUIRED_FIELDS = {"username", "email", "language", "request_id", "timestamp"}


class CompletenessValidator(BaseValidator):
    """Ensures required top‑level fields are provided and non‑empty."""

    def _validate(self, context) -> ValidationResult:
        data = context.data
        missing = [
            field
            for field in REQUIRED_FIELDS
            if field not in data or is_empty(data.get(field))
        ]
        if missing:
            return ValidationResult(
                success=False,
                validator_name=self.__class__.__name__,
                message=f"Missing required fields: {', '.join(missing)}",
                details={"missing_fields": missing},
            )
        return ValidationResult(
            success=True,
            validator_name=self.__class__.__name__,
            message="All required fields are present.",
        )
