# models.py
"""Data models for the Input Validator module.

Defines the structures used to convey validation outcomes.
"""

from dataclasses import dataclass
from typing import List, Any, Dict


@dataclass
class ValidationResult:
    """Result of a single validator.

    Attributes:
        success: Whether the validator passed.
        validator_name: Name of the validator class.
        message: Human‑readable explanation of the result.
        details: Optional dictionary with validator‑specific data.
    """
    success: bool
    validator_name: str
    message: str = ""
    details: Dict[str, Any] = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}


@dataclass
class InputValidationResponse:
    """Aggregated response from the whole validation pipeline.

    Attributes:
        success: Overall success – ``True`` only if *all* validators succeeded.
        results: List of :class:`ValidationResult` objects in execution order.
    """
    success: bool
    results: List[ValidationResult]
