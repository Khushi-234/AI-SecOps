# format.py
"""Validator that checks values against expected formats using regular expressions.

For demonstration purposes, this validator includes a simple email pattern check.
Extend ``FORMAT_RULES`` with additional field‑specific patterns as needed.
"""

from .base_validator import BaseValidator
from ..models import ValidationResult
from ..utils import matches_regex, is_empty

# Example format rules: field name -> regex pattern
FORMAT_RULES = {
    "email": r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",
    # Add more field‑specific patterns here.
}


class FormatValidator(BaseValidator):
    """Validates that fields match their declared regex patterns.
    """

    def _validate(self, context) -> ValidationResult:
        data = context.data
        mismatches = []
        for field, pattern in FORMAT_RULES.items():
            value = data.get(field)
            if value is None or is_empty(value):
                continue  # Skip missing/empty; other validators handle presence.
            if not isinstance(value, str):
                mismatches.append(field)
                continue
            if not matches_regex(pattern, value):
                mismatches.append(field)
        if mismatches:
            return ValidationResult(
                success=False,
                validator_name=self.__class__.__name__,
                message=f"Format validation failed for fields: {', '.join(mismatches)}",
                details={"fields": mismatches},
            )
        return ValidationResult(
            success=True,
            validator_name=self.__class__.__name__,
            message="All formatted fields match expected patterns.",
        )