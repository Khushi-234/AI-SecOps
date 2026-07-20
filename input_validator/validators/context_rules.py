# context_rules.py
"""Validator that checks for required context-specific keys.

For illustration, this validator ensures that a ``request_id`` and ``timestamp``
are present in the input data. Extend ``REQUIRED_CONTEXT_KEYS`` as needed.
"""

from .base_validator import BaseValidator
from ..models import ValidationResult
from ..utils import is_empty

REQUIRED_CONTEXT_KEYS = {"request_id", "timestamp"}


class ContextRulesValidator(BaseValidator):
    """Ensures required context keys exist and are non‑empty."""

    def _validate(self, context) -> ValidationResult:
        data = context.data
        missing = [
            key
            for key in REQUIRED_CONTEXT_KEYS
            if key not in data or is_empty(data.get(key))
        ]
        if missing:
            return ValidationResult(
                success=False,
                validator_name=self.__class__.__name__,
                message=f"Missing required context keys: {', '.join(missing)}",
                details={"missing_keys": missing},
            )
        return ValidationResult(
            success=True,
            validator_name=self.__class__.__name__,
            message="All required context keys are present.",
        )
