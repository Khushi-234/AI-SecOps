# encoding.py
"""Validator that ensures provided byte data is valid UTF‑8 encoding.

If a value in the input dict is of type ``bytes`` it is checked via
:func:`utils.is_valid_utf8`. Any failure results in a validation error.
"""

from .base_validator import BaseValidator
from ..models import ValidationResult
from ..utils import is_valid_utf8, is_empty


class EncodingValidator(BaseValidator):
    """Validates UTF‑8 encoding for byte fields.
    """

    def _validate(self, context) -> ValidationResult:
        data = context.data
        invalid_keys = []
        for key, value in data.items():
            if isinstance(value, bytes) and not is_empty(value):
                if not is_valid_utf8(value):
                    invalid_keys.append(key)
        if invalid_keys:
            return ValidationResult(
                success=False,
                validator_name=self.__class__.__name__,
                message=f"Invalid UTF‑8 encoding for keys: {', '.join(invalid_keys)}",
                details={"invalid_keys": invalid_keys},
            )
        return ValidationResult(
            success=True,
            validator_name=self.__class__.__name__,
            message="All byte fields are valid UTF‑8.",
        )