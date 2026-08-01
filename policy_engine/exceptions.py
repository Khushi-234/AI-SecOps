"""
Exception Hierarchy for the Policy Engine.

Defines a centralized exception taxonomy for policy evaluation, rule execution,
sanitization pipeline operations, and configuration management.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class PolicyEngineError(Exception):
    """
    Abstract base exception for all domain errors within the Policy Engine framework.
    """

    __slots__ = ("_message", "_details", "_timestamp")

    def __init__(
        self,
        message: str,
        field: str | None = None,
        value: Any | None = None,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None,
    ) -> None:
        """Initializes the exception with message, optional metadata, and optional cause."""
        super().__init__(message)
        self._message: str = message
        combined_details = dict(details) if details else {}
        if field is not None:
            combined_details["field"] = field
        if value is not None:
            combined_details["value"] = value
        self._details: dict[str, Any] = combined_details
        self._timestamp: datetime = datetime.now(timezone.utc)
        if cause is not None:
            self.__cause__ = cause

    @property
    def message(self) -> str:
        """Returns the error message."""
        return self._message

    @property
    def details(self) -> dict[str, Any]:
        """Returns diagnostic details."""
        return dict(self._details)

    @property
    def timestamp(self) -> datetime:
        """Returns timezone-aware UTC timestamp of error instantiation."""
        return self._timestamp

    def to_dict(self) -> dict[str, Any]:
        """Serializes error object to audit dictionary."""
        return {
            "error_type": self.__class__.__name__,
            "message": self._message,
            "details": dict(self._details),
            "timestamp": self._timestamp.isoformat(),
        }


class InvalidPolicyInputError(PolicyEngineError):
    """Raised when policy evaluation input payload (e.g. RiskContext) is missing or invalid."""

    pass


class PolicyConfigurationError(PolicyEngineError):
    """Raised when PolicyEngine threshold settings or rule configurations are invalid."""

    pass


class PolicyExecutionError(PolicyEngineError):
    """Raised when rule evaluation or decision mapping encounters an internal runtime failure."""

    pass

