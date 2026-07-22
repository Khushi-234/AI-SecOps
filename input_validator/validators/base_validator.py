"""
Abstract Base Validator for the Input Validator framework.

Purpose:
    Exposes a unified interface and lifecycle orchestration for prompt validation checks.

Responsibilities:
    - Timing instrumentation (via time.perf_counter).
    - Lifecycle delegation via the Template Method Pattern.
    - Standardized result wrapping, exception isolation, and pre-validation logic.

Execution Lifecycle:
    Input Prompt -> Start Timer -> _validate_input() -> _validate() -> End Timer -> Telemetry packaging -> ValidationResult.

Extensibility:
    New validators subclass BaseValidator and implement the protected _validate() hook.
    Validator specific settings are injected via ValidatorConfig.

Thread Safety:
    Validators are stateless; they do not write to instance attributes during validate().
    This ensures thread-safe parallel processing across async execution requests.

Error Handling:
    Recoverable failures (ValidationError) return a failed ValidationResult. Unrecoverable
    failures are wrapped inside ValidationExecutionError and raised.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import time
from typing import Any

from input_validator.exceptions import ValidationError, ValidationExecutionError
from input_validator.models import ValidationResult


class BaseValidator(ABC):
    """
    Abstract orchestrator managing validation lifecycles and timings.

    All Sprint 6 validators must inherit from this abstraction.
    """

    def __init__(self, config: Any) -> None:
        """Initializes the base validator with its corresponding ValidatorConfig."""
        self.config = config

    @property
    @abstractmethod
    def validator_name(self) -> str:
        """The identifying name of the validator class."""
        pass

    @abstractmethod
    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        """Hook method implemented by subclasses to perform check logic."""
        pass

    def validate(
        self, prompt: str, context: dict[str, Any] | None = None
    ) -> ValidationResult:
        """
        Executes the complete validation lifecycle using the Template Method Pattern.

        Runs sanity checks, measures execution duration, packages success/failure metrics,
        and isolates unexpected validation crashes.
        """
        start_time = time.perf_counter()
        ctx = context or {}
        try:
            # Generic framework pre-validation checks
            self._validate_input(prompt)

            is_valid, error_message, metadata = self._validate(prompt, ctx)
            elapsed_ms = self._measure_execution_time(start_time)

            if is_valid:
                return self._build_success_result(elapsed_ms, metadata, ctx)
            return self._build_failure_result(
                error_message or "Validation failed", elapsed_ms, metadata, ctx
            )
        except ValidationError as e:
            # Recoverable validation errors return a failed result instead of throwing
            elapsed_ms = self._measure_execution_time(start_time)
            return self._build_failure_result(
                error_message=e.message,
                elapsed_ms=elapsed_ms,
                metadata=e.details,
                context=ctx,
            )
        except Exception as e:
            raise self._handle_exception(e) from e

    def _validate_input(self, prompt: str) -> None:
        """Performs generic framework-level sanity checks on the input prompt."""
        if not isinstance(prompt, str):
            raise ValidationError(
                message=f"Input prompt must be a string, got {type(prompt).__name__}",
                details={"validator_name": self.validator_name},
            )

    def _measure_execution_time(self, start_time: float) -> float:
        """Calculates elapsed time in milliseconds from a starting high-resolution counter."""
        return (time.perf_counter() - start_time) * 1000.0

    def _current_timestamp(self) -> datetime:
        """Returns the current timezone-aware UTC datetime."""
        return datetime.now(timezone.utc)

    def _handle_exception(self, e: Exception) -> Exception:
        """Wraps unexpected validator failures inside ValidationExecutionError."""
        if isinstance(e, ValidationExecutionError):
            return e
        return ValidationExecutionError(
            message=f"Unexpected crash in validator '{self.validator_name}': {e}",
            details={"validator_name": self.validator_name},
            cause=e,
        )

    def _propagate_context(
        self, metadata: dict[str, Any] | None, context: dict[str, Any]
    ) -> dict[str, Any]:
        """Injects request_id from context into metadata dictionary for traceability."""
        meta = dict(metadata) if metadata else {}
        if "request_id" in context and "request_id" not in meta:
            meta["request_id"] = context["request_id"]
        return meta

    def _build_success_result(
        self,
        elapsed_ms: float,
        metadata: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> ValidationResult:
        """Builds a successful validation result object."""
        ctx = context or {}
        return ValidationResult(
            validator_name=self.validator_name,
            is_valid=True,
            error_message=None,
            execution_time_ms=elapsed_ms,
            timestamp=self._current_timestamp(),
            metadata=self._propagate_context(metadata, ctx),
        )

    def _build_failure_result(
        self,
        error_message: str,
        elapsed_ms: float,
        metadata: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> ValidationResult:
        """Builds a failed validation result object."""
        ctx = context or {}
        return ValidationResult(
            validator_name=self.validator_name,
            is_valid=False,
            error_message=error_message,
            execution_time_ms=elapsed_ms,
            timestamp=self._current_timestamp(),
            metadata=self._propagate_context(metadata, ctx),
        )
