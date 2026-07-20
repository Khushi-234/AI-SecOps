# input_validator.py
"""Public API for the Input Validator module.

Provides a single entry point function `validate_input` that runs the validation pipeline
and returns an :class:`InputValidationResponse`.
"""

from .pipeline import run_validation_pipeline
from .models import InputValidationResponse


def validate_input(data: dict) -> InputValidationResponse:
    """Validate the provided input data.

    Args:
        data: Dictionary representing the input to be validated.

    Returns:
        InputValidationResponse: Result of the validation process.
    """
    return run_validation_pipeline(data)
