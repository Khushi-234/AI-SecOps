"""
Exception Hierarchy for the Risk Engine — Sprint 7.

Defines a centralized, enterprise-grade exception taxonomy for risk aggregation,
scoring calculation, confidence evaluation, policy mapping, and runtime execution.

Design Principles:
    - SOLID: Single responsibility per exception class.
    - DRY: Centralized base constructor delegation and telemetry serialization.
    - Fail-Secure: Standardized exception wrapping for unhandled execution faults.
    - Thread Safety: Immutable property design ensuring thread-safe audit logging.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class RiskEngineError(Exception):
    """
    Abstract base exception for all domain errors within the Risk Engine framework.

    Responsibilities:
        - Acts as common parent for all Risk Engine exception types.
        - Captures human-readable error message and UTC timestamp.
        - Holds structured diagnostic metadata dictionary (`details`).
        - Supports Python exception chaining via explicit `cause` parameter.
        - Provides immutable read-only properties for thread safety.

    Usage:
        raise RiskEngineError("Failure occurred", details={"request_id": "123"}, cause=original_exc)
    """

    __slots__ = ("_message", "_details", "_timestamp")

    def __init__(
        self,
        message: str,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None,
    ) -> None:
        """Initializes the exception with message, structured metadata, and optional cause."""
        super().__init__(message)
        self._message: str = message
        self._details: dict[str, Any] = dict(details) if details else {}
        self._timestamp: datetime = datetime.now(timezone.utc)
        if cause is not None:
            self.__cause__ = cause

    @property
    def message(self) -> str:
        """Returns the human-readable error message."""
        return self._message

    @property
    def details(self) -> dict[str, Any]:
        """Returns a read-only copy of the structured details dictionary."""
        return dict(self._details)

    @property
    def timestamp(self) -> datetime:
        """Returns the timezone-aware UTC timestamp when the exception was raised."""
        return self._timestamp

    def to_dict(self) -> dict[str, Any]:
        """
        Serializes exception state to a dictionary suitable for SIEM, OpenTelemetry,
        and audit log payloads.
        """
        return {
            "error_type": self.__class__.__name__,
            "message": self._message,
            "details": self._details,
            "timestamp": self._timestamp.isoformat(),
            "cause": (
                f"{type(self.__cause__).__name__}: {self.__cause__}"
                if self.__cause__
                else None
            ),
        }

    def __str__(self) -> str:
        formatted = f"[{self.__class__.__name__}] {self._message}"
        if self._details:
            formatted += f" (Details: {self._details})"
        if self.__cause__:
            formatted += (
                f" | Caused by: {type(self.__cause__).__name__}({self.__cause__})"
            )
        return formatted

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self._message!r}, "
            f"details={self._details!r}, "
            f"timestamp={self._timestamp.isoformat()!r})"
        )


# ===========================================================================
# Domain Exception Subclasses
# ===========================================================================


class RiskEngineConfigurationError(RiskEngineError):
    """
    Raised when Risk Engine configuration validation fails.

    Adds structured field/value metadata while preserving the
    base exception behaviour.
    """

    def __init__(
        self,
        message: str,
        field: str | None = None,
        value: Any | None = None,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None,
    ) -> None:

        combined_details = dict(details) if details else {}

        if field is not None:
            combined_details["field"] = field

        if value is not None:
            combined_details["value"] = value

        super().__init__(
            message=message,
            details=combined_details,
            cause=cause,
        )

class RiskAggregationError(RiskEngineError):
    """
    Raised when multi-module finding aggregation or conflict resolution fails.

    Responsibilities:
        - Indicates malformed detector outputs, merging errors, or failed deduplication.
    """


class RiskScoringError(RiskEngineError):
    """
    Base exception for failures occurring during risk score computation.

    Responsibilities:
        - Parent class for granular scoring strategy exceptions.
    """


class CompositeScoringError(RiskScoringError):
    """
    Raised when non-linear or hybrid multi-strategy composite scoring fails.

    Responsibilities:
        - Indicates composite amplification or score aggregation failure.
    """


class ThresholdEvaluationError(RiskScoringError):
    """
    Raised when assigning risk levels against threshold boundaries fails.

    Responsibilities:
        - Indicates threshold evaluation boundary violations or missing tier mappings.
    """


class AdaptiveScoringError(RiskScoringError):
    """
    Raised when contextual or historical adaptive score adjustment encounters an error.

    Responsibilities:
        - Indicates failure during dynamic weight tuning or historical baseline evaluation.
    """


class ConfidenceCalculationError(RiskEngineError):
    """
    Raised when calculating mathematical confidence or consensus index fails.

    Responsibilities:
        - Indicates entropy calculation error or invalid detector confidence signal.
    """


class PolicyMappingError(RiskEngineError):
    """
    Raised when mapping composite risk assessments to policy recommendations fails.

    Responsibilities:
        - Indicates unknown risk level or recommendation mapping error.
    """


class InvalidRiskInputError(RiskEngineError):
    """
    Raised when an ingested `RiskInputBundle` is malformed, missing, or unparseable.

    Responsibilities:
        - Indicates missing correlation IDs, null firewall responses, or invalid payloads.
    """


class RiskValidationError(RiskEngineError):
    """
    Raised when internal risk engine data models fail domain validation constraints.

    Responsibilities:
        - Indicates schema boundary failure or un-normalized score values.
    """


class RiskEngineExecutionError(RiskEngineError):
    """
    Raised when an unhandled runtime error occurs during pipeline execution (Fail-Secure).

    Responsibilities:
        - Wraps unexpected exceptions to guarantee system fails securely to a safe state.

    Usage:
        raise RiskEngineExecutionError.wrap(unhandled_exc, details={"stage": "scoring"})
    """

    @classmethod
    def wrap(
        cls,
        cause: Exception,
        message: str = "Execution failed securely due to an unhandled runtime error.",
        details: dict[str, Any] | None = None,
    ) -> RiskEngineExecutionError:
        """
        Factory method to wrap an arbitrary unhandled exception into a fail-secure
        RiskEngineExecutionError instance.
        """
        combined_details = dict(details) if details else {}
        combined_details["original_error_type"] = type(cause).__name__
        return cls(message=message, details=combined_details, cause=cause)


class UnsupportedScoringStrategyError(RiskEngineConfigurationError):
    """
    Raised when an unrecognized or unregistered scoring strategy is requested.

    Responsibilities:
        - Indicates requested strategy name is not registered in strategy factory/registry.
    """
