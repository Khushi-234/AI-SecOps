"""
ValidationPipeline execution engine.

Purpose:
    Orchestrates sequential validation of input prompts against registered validation checks.

Execution Flow:
    Pipeline Trigger -> before_pipeline() hook -> Priority-ordered sequential check execution
    -> Early stopping (fail-fast check) -> Telemetry aggregate -> after_pipeline() hook -> Return Response.

Responsibilities:
    - Dynamic registration and unregistration of BaseValidator instances.
    - Context normalization and safe propagation.
    - Early execution halts (fail-fast) on check violations.
    - Pipeline timing instrumentation and summary telemetry calculation.

Extensibility:
    Third-party validators are registered dynamically, executing seamlessly according to their
    priority parameters. Pluggable telemetry is supported via before/after lifecycle hooks.

Thread Safety:
    Pipeline instances do not modify internal state or validator variables during execution.
    Validators are treated as immutable execution components.

Error Handling:
    Validates components during registration, throwing ValidatorRegistrationError on duplicates.
    Wraps execution errors gracefully into standard ValidationResult representations.
"""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
import time
from typing import Any

from input_validator.config import PipelineConfig
from input_validator.exceptions import ValidatorRegistrationError
from input_validator.models import InputValidationResponse, ValidationResult
from input_validator.utils import (
    compute_execution_time_ms,
    is_validator_enabled,
    normalize_context,
)
from input_validator.base_validator import BaseValidator


class ValidationPipeline:
    """
    Central orchestrator managing registered prompt validation steps.

    Validation is dispatched sequentially based on validator execution priorities.
    """

    def __init__(self, validators: list[BaseValidator], config: PipelineConfig) -> None:
        """Initializes the execution pipeline with injected config and validators list."""
        self._config = config
        self._validators: OrderedDict[str, BaseValidator] = OrderedDict()
        for validator in validators:
            self.register_validator(validator)

    def register_validator(self, validator: BaseValidator) -> None:
        """Registers a unique validator instance in the pipeline."""
        if not isinstance(validator, BaseValidator):
            raise ValidatorRegistrationError(
                "Cannot register non-BaseValidator components"
            )

        name = validator.validator_name
        if name in self._validators:
            raise ValidatorRegistrationError(
                f"Validator with name '{name}' is already registered in this pipeline."
            )

        priority = getattr(validator, "priority", 100)
        for existing in self._validators.values():
            if getattr(existing, "priority", 100) == priority:
                raise ValidatorRegistrationError(
                    f"A validator with priority '{priority}' is already registered in this pipeline."
                )

        self._validators[name] = validator

    def unregister_validator(self, validator_name: str) -> None:
        """Unregisters a validator instance by its class name."""
        if validator_name not in self._validators:
            raise ValidatorRegistrationError(
                f"No validator with name '{validator_name}' is currently registered."
            )
        del self._validators[validator_name]

    def get_registered_validators(self) -> list[BaseValidator]:
        """Returns registered validator instances sorted by ascending priority."""
        return sorted(
            self._validators.values(), key=lambda v: getattr(v, "priority", 100)
        )

    def validate(
        self, prompt: str, context: dict[str, Any] | None = None
    ) -> InputValidationResponse:
        """
        Runs the prompt sequentially through all priority-sorted enabled validators.

        Respects the fail_fast setting, stopping pipeline checks immediately on failure.
        """
        start_time = time.perf_counter()
        ctx = normalize_context(context)

        self._before_pipeline(prompt, ctx)
        results: list[ValidationResult] = []
        is_pipeline_valid = True

        successful_validators: list[str] = []
        failed_validators: list[str] = []
        skipped_validators: list[str] = []
        fail_fast_triggered = False

        # Freeze the execution list to prevent changes during validation pipeline iteration
        validators_tuple = tuple(self.get_registered_validators())

        for validator in validators_tuple:
            result = self._execute_validator(validator, prompt, ctx)
            results.append(result)

            if result.metadata.get("skipped"):
                skipped_validators.append(validator.validator_name)
            elif result.is_valid:
                successful_validators.append(validator.validator_name)
            else:
                failed_validators.append(validator.validator_name)
                is_pipeline_valid = False
                # Halts immediately on validation failure if fail_fast is enabled
                if self._config.fail_fast:
                    fail_fast_triggered = True
                    break

        elapsed_ms = compute_execution_time_ms(start_time)
        response = self._aggregate_results(
            results,
            elapsed_ms,
            is_pipeline_valid,
            successful_validators,
            failed_validators,
            skipped_validators,
            fail_fast_triggered,
        )

        self._after_pipeline(response)
        return response

    # ===========================================================================
    # Reusable Protected Helper Methods (DRY Enforcement)
    # ===========================================================================

    def _execute_validator(
        self, validator: BaseValidator, prompt: str, context: dict[str, Any]
    ) -> ValidationResult:
        """Runs validation checks on a single validator instance, tracking lifecycle hooks."""
        self._before_validator(validator, prompt, context)

        if not is_validator_enabled(validator):
            skipped_result = self._build_skipped_result(validator)
            self._after_validator(validator, skipped_result)
            return skipped_result

        result = validator.validate(prompt, context)
        self._after_validator(validator, result)
        return result

    def _build_skipped_result(self, validator: BaseValidator) -> ValidationResult:
        """Builds a standardized skipped ValidationResult for a disabled validator."""
        return ValidationResult(
            validator_name=validator.validator_name,
            is_valid=True,
            error_message=None,
            execution_time_ms=0.0,
            timestamp=datetime.now(timezone.utc),
            metadata={"skipped": True, "reason": "Disabled by configuration"},
        )

    def _aggregate_results(
        self,
        results: list[ValidationResult],
        elapsed_ms: float,
        is_valid: bool,
        successful: list[str],
        failed: list[str],
        skipped: list[str],
        fail_fast_triggered: bool,
    ) -> InputValidationResponse:
        """Assembles the final InputValidationResponse DTO."""
        summary_metadata = {
            "total_validators": len(self._validators),
            "executed_validators": len(results),
            "successful_validators": successful,
            "failed_validators": failed,
            "skipped_validators": skipped,
            "pipeline_failed": not is_valid,
            "fail_fast_triggered": fail_fast_triggered,
            "execution_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return InputValidationResponse(
            is_valid=is_valid,
            results=results,
            execution_time_ms=elapsed_ms,
            metadata=summary_metadata,
        )

    # ===========================================================================
    # Telemetry Lifecycle Hooks (Future Hooks Extensions)
    # ===========================================================================

    def _before_pipeline(self, prompt: str, context: dict[str, Any]) -> None:
        """Lifecycle hook executed before the pipeline begins validation checks."""
        pass

    def _after_pipeline(self, response: InputValidationResponse) -> None:
        """Lifecycle hook executed after the pipeline completes validation checks."""
        pass

    def _before_validator(
        self, validator: BaseValidator, prompt: str, context: dict[str, Any]
    ) -> None:
        """Lifecycle hook executed before a single validator check runs."""
        pass

    def _after_validator(
        self, validator: BaseValidator, result: ValidationResult
    ) -> None:
        """Lifecycle hook executed after a single validator check completes."""
        pass
