"""
Custom exceptions for the Output Guard module.
"""

from __future__ import annotations


class OutputGuardError(Exception):
    """Base exception for all Output Guard errors."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} (details: {self.details})"
        return self.message


class SanitizationError(OutputGuardError):
    """Raised when an individual sanitizer encounters a failure during execution."""

    def __init__(
        self,
        message: str,
        sanitizer_name: str | None = None,
        details: dict | None = None,
    ) -> None:
        merged_details = details or {}
        if sanitizer_name:
            merged_details["sanitizer_name"] = sanitizer_name
        super().__init__(message, details=merged_details)
        self.sanitizer_name = sanitizer_name


class InvalidOutputError(OutputGuardError):
    """Raised when the input LLM output is invalid (e.g., None, non-string, or exceeds limits)."""

    pass


class ConfigurationError(OutputGuardError):
    """Raised when an invalid Output Guard configuration is provided."""

    pass


class OutputGuardExecutionError(OutputGuardError):
    """Raised when pipeline execution fails or fail-secure error enforcement triggers."""

    pass


__all__ = [
    "OutputGuardError",
    "SanitizationError",
    "InvalidOutputError",
    "ConfigurationError",
    "OutputGuardExecutionError",
]

