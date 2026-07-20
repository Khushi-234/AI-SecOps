# schema.py
"""Validator that ensures input data conforms to a predefined schema.

For demonstration, a minimal JSON‑schema‑like dictionary is defined in
``SCHEMA_DEFINITION``. The validator checks that required keys exist and
that each value matches the expected type. In a real system this could be
replaced with ``jsonschema.validate``.
"""

from .base_validator import BaseValidator
from ..models import ValidationResult
from ..utils import is_empty

# Simple schema definition: field -> expected Python type
SCHEMA_DEFINITION = {
    "username": str,
    "email": str,
    "age": int,
    "profile": dict,
}


class SchemaValidator(BaseValidator):
    """Validates that the input respects ``SCHEMA_DEFINITION``.
    """

    def _validate(self, context) -> ValidationResult:
        data = context.data
        missing = []
        type_mismatches = []
        for field, expected_type in SCHEMA_DEFINITION.items():
            if field not in data or is_empty(data[field]):
                missing.append(field)
                continue
            if not isinstance(data[field], expected_type):
                type_mismatches.append(field)
        if missing or type_mismatches:
            messages = []
            details = {}
            if missing:
                messages.append(f"Missing required fields: {', '.join(missing)}")
                details["missing"] = missing
            if type_mismatches:
                messages.append(
                    f"Type mismatches for fields: {', '.join(type_mismatches)}"
                )
                details["type_mismatches"] = type_mismatches
            return ValidationResult(
                success=False,
                validator_name=self.__class__.__name__,
                message="; ".join(messages),
                details=details,
            )
        return ValidationResult(
            success=True,
            validator_name=self.__class__.__name__,
            message="Input matches schema definition.",
        )
