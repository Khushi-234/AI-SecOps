"""
Exception hierarchy and error codes for the Input Validator framework.

Defines custom exception classes with base constructor delegation, Slots support,
ErrorCode enum mapping, serializability, and exception chaining.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ErrorCode(Enum):
    """
    Enumeration of framework and validation failure codes.

    Used for telemetry logging, debugging, and client response mapping.
    """

    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    VALIDATION_EXECUTION_ERROR = "VALIDATION_EXECUTION_ERROR"
    VALIDATION_TIMEOUT = "VALIDATION_TIMEOUT"
    VALIDATION_CANCELLED = "VALIDATION_CANCELLED"
    VALIDATOR_NOT_REGISTERED = "VALIDATOR_NOT_REGISTERED"
    VALIDATOR_INITIALIZATION_FAILED = "VALIDATOR_INITIALIZATION_FAILED"
    SCHEMA_ERROR = "SCHEMA_ERROR"
    LANGUAGE_ERROR = "LANGUAGE_ERROR"
    ENCODING_ERROR = "ENCODING_ERROR"
    FILE_ERROR = "FILE_ERROR"
    CONTEXT_ERROR = "CONTEXT_ERROR"
    COMPLETENESS_ERROR = "COMPLETENESS_ERROR"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


class InputValidatorError(Exception):
    """
    Base exception for all errors within the Input Validator framework.

    This exception incorporates support for exception chaining, serialization,
    and recovery flags, making it suitable for telemetry, audit logging, and
    API error reporting.

    Attributes:
        message (str): Explanatory error message.
        error_code (ErrorCode): Mapped error code categorization.
        details (dict[str, Any]): Telemetry or contextual metadata.
        recoverable (bool): Flag indicating if the pipeline can continue execution.
        timestamp (datetime): Timezone-aware UTC timestamp of the error occurrence.
        __cause__ (Exception | None): Underlying source exception chained via standard Python rules.
    """

    __slots__ = ("message", "error_code", "details", "recoverable", "timestamp")

    def __init__(
        self,
        message: str,
        error_code: ErrorCode = ErrorCode.UNKNOWN_ERROR,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None,
        recoverable: bool = False,
    ) -> None:
        """Initializes the exception with telemetry properties and optional chaining."""
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.recoverable = recoverable
        self.timestamp = datetime.now(timezone.utc)
        if cause is not None:
            self.__cause__ = cause

    def to_dict(self) -> dict[str, Any]:
        """
        Returns a serializable dictionary representation of the exception.

        Useful for logging, audit trails, and REST API error formatting.
        """
        return {
            "message": self.message,
            "error_code": self.error_code.value,
            "details": self.details,
            "recoverable": self.recoverable,
            "timestamp": self.timestamp.isoformat(),
            "cause": str(self.__cause__) if self.__cause__ else None,
        }

    def __str__(self) -> str:
        formatted = f"[{self.error_code.value}] {self.message}"
        if self.details:
            formatted += f" (Details: {self.details})"
        if self.__cause__:
            formatted += f" | Cause: {type(self.__cause__).__name__}({self.__cause__})"
        return formatted

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"error_code={self.error_code.value}, "
            f"message={self.message!r}, "
            f"recoverable={self.recoverable}, "
            f"timestamp={self.timestamp.isoformat()}"
            f")"
        )


# ===========================================================================
# Framework Failure Exceptions (Directly subclassing InputValidatorError)
# ===========================================================================


class ConfigurationError(InputValidatorError):
    """Raised when config parameters are invalid or parsing fails."""

    def __init__(
        self,
        message: str,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(
            message, ErrorCode.CONFIGURATION_ERROR, details, cause, recoverable=False
        )


class ValidatorRegistrationError(InputValidatorError):
    """Raised when registering a validator component fails."""

    def __init__(
        self,
        message: str,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(
            message,
            ErrorCode.VALIDATOR_NOT_REGISTERED,
            details,
            cause,
            recoverable=False,
        )


class ValidatorInitializationError(InputValidatorError):
    """Raised when constructing/instantiating a validator component fails."""

    def __init__(
        self,
        message: str,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(
            message,
            ErrorCode.VALIDATOR_INITIALIZATION_FAILED,
            details,
            cause,
            recoverable=False,
        )


# ===========================================================================
# Validation Exceptions (Subclassing ValidationError)
# ===========================================================================


class ValidationError(InputValidatorError):
    """Base exception for all recoverable prompt validation failures."""

    def __init__(
        self,
        message: str,
        error_code: ErrorCode = ErrorCode.VALIDATION_ERROR,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None,
        recoverable: bool = True,
    ) -> None:
        super().__init__(message, error_code, details, cause, recoverable)


class ValidationExecutionError(ValidationError):
    """Raised when validation execution logic crashes unexpectedly."""

    def __init__(
        self,
        message: str,
        error_code: ErrorCode = ErrorCode.VALIDATION_EXECUTION_ERROR,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message, error_code, details, cause)


class ValidationTimeoutError(ValidationExecutionError):
    """Raised when validation execution exceeds allowed pipeline duration."""

    def __init__(
        self,
        message: str,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message, ErrorCode.VALIDATION_TIMEOUT, details, cause)


class ValidationCancelledError(ValidationExecutionError):
    """Raised when validation execution is aborted prior to completion."""

    def __init__(
        self,
        message: str,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message, ErrorCode.VALIDATION_CANCELLED, details, cause)


class SchemaValidationError(ValidationError):
    """Raised when structured input payloads violate schema specifications."""

    def __init__(
        self,
        message: str,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message, ErrorCode.SCHEMA_ERROR, details, cause)


class LanguageValidationError(ValidationError):
    """Raised when prompt language checks fall outside allowed supported limits."""

    def __init__(
        self,
        message: str,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message, ErrorCode.LANGUAGE_ERROR, details, cause)


class EncodingValidationError(ValidationError):
    """Raised when prompt encoding violates security requirements."""

    def __init__(
        self,
        message: str,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message, ErrorCode.ENCODING_ERROR, details, cause)


class FileValidationError(ValidationError):
    """Raised when uploaded file properties violate safety checks."""

    def __init__(
        self,
        message: str,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message, ErrorCode.FILE_ERROR, details, cause)


class ContextValidationError(ValidationError):
    """Raised when prompt violates context validation rules."""

    def __init__(
        self,
        message: str,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message, ErrorCode.CONTEXT_ERROR, details, cause)


class CompletenessValidationError(ValidationError):
    """Raised when input lacks required semantic completeness fields."""

    def __init__(
        self,
        message: str,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message, ErrorCode.COMPLETENESS_ERROR, details, cause)
