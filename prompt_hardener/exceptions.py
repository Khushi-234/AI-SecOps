"""
Custom Exception Hierarchy for the Prompt Hardener module.
"""

from __future__ import annotations


class HardeningError(Exception):
    """Base exception class for all errors in the Prompt Hardener module."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class RuleExecutionError(HardeningError):
    """Raised when an error occurs during security rule evaluation."""

    pass


class InjectionError(HardeningError):
    """Raised when prompt injection processing fails."""

    pass


class InvalidPromptError(HardeningError):
    """Raised when input prompt is invalid or exceeds bounds."""

    pass


class ConfigurationError(HardeningError):
    """Raised when hardener configuration is invalid."""

    pass


__all__ = [
    "HardeningError",
    "RuleExecutionError",
    "InjectionError",
    "InvalidPromptError",
    "ConfigurationError",
]
