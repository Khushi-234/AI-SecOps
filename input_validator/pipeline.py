# pipeline.py
"""Execution pipeline for input validation.

The pipeline loads configured validator classes, runs them sequentially on the input data,
and aggregates their results into an :class:`InputValidationResponse`.
"""

from typing import List

from .config import VALIDATOR_CLASSES
from .models import InputValidationResponse, ValidationResult
from .context import ValidationContext
from .exceptions import ValidationPipelineException
from .logger import validator_logger


def run_validation_pipeline(data: dict) -> InputValidationResponse:
    """Run the validation pipeline on the provided data.

    Args:
        data: Input dictionary to be validated.

    Returns:
        InputValidationResponse: Aggregated validation outcome.
    """
    context = ValidationContext(data=data)
    results: List[ValidationResult] = []
    try:
        for validator_cls in VALIDATOR_CLASSES:
            validator = validator_cls()
            result = validator.validate(context)
            results.append(result)
            validator_logger.debug(
                f"Validator {validator.__class__.__name__} result: {result.success}"
            )
            if not result.success:
                # Early exit on failure if desired; here we continue to collect all.
                continue
    except Exception as exc:
        raise ValidationPipelineException(str(exc))

    overall_success = all(r.success for r in results)
    return InputValidationResponse(success=overall_success, results=results)
