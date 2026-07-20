# exceptions.py
"""Custom exception hierarchy for the Input Validator module.
"""

class ValidationException(Exception):
    """Base class for validation‑related exceptions."""
    pass

class ValidationPipelineException(ValidationException):
    """Raised when an unexpected error occurs inside the validation pipeline."""
    pass
