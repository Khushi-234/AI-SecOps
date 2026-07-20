# length.py
"""Validator that checks length constraints for string fields.

Iterates over the input data and ensures each string value's length is within
the allowed bounds (default 1‑1024). Uses :func:`utils.within_length`.
"""

from .base_validator import BaseValidator
from ..models import ValidationResult
from ..utils import within_length, is_empty


class LengthValidator(BaseValidator):
    """Ensures string values respect length limits.
    """

    def _validate(self, context) -> ValidationResult:
        data = context.data
        violations = []
        for key, value in data.items():
            if isinstance(value, str) and not is_empty(value):
                if not within_length(value):
                    violations.append(key)
        if violations:
            return ValidationResult(
                success=False,
                validator_name=self.__class__.__name__,
                message=f"Values exceed length limits for keys: {', '.join(violations)}",
                details={"keys": violations},
            )
        return ValidationResult(
            success=True,
            validator_name=self.__class__.__name__,
            message="All string lengths within limits.",
        )
