# empty.py
"""Validator that checks for empty values in the input data.

If any top‑level value is empty (as defined by :func:`utils.is_empty`), the
validation fails.
"""

from .base_validator import BaseValidator
from ..models import ValidationResult
from ..utils import is_empty


class EmptyValidator(BaseValidator):
    """Ensures no required field is empty.
    """

    def _validate(self, context) -> ValidationResult:
        data = context.data
        empty_keys = [k for k, v in data.items() if is_empty(v)]
        if empty_keys:
            return ValidationResult(
                success=False,
                validator_name=self.__class__.__name__,
                message=f"Empty values found for keys: {', '.join(empty_keys)}",
                details={"empty_keys": empty_keys},
            )
        return ValidationResult(
            success=True,
            validator_name=self.__class__.__name__,
            message="All fields contain non‑empty values.",
        )
