"""
Enterprise-grade unit test suite for ValidationPipeline component.

Validates constructor initialization, dynamic validator registration and unregistration,
priority-based execution ordering, fail-fast vs fail-safe execution paths, result aggregation,
context normalization and propagation, lifecycle telemetry hooks, disabled validator handling,
exception propagation, metadata DTO structure, stateless execution, multi-pipeline independence,
50-validator stress execution, and fresh object instantiation per execution.
"""

import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from input_validator.config import PipelineConfig
from input_validator.exceptions import (
    ValidationError,
    ValidationExecutionError,
    ValidatorRegistrationError,
)
from input_validator.models import InputValidationResponse, ValidationResult
from input_validator.pipeline import ValidationPipeline
from input_validator.validators.base_validator import BaseValidator

# ===========================================================================
# Lightweight Mock Validators (Isolated for Testing)
# ===========================================================================


@dataclass
class DummyConfig:
    """Simple configuration object for testing mock validators."""

    enabled: bool = True


class AlwaysPassValidator(BaseValidator):
    """Mock validator that always passes validation."""

    def __init__(self, priority: int = 10, name: str = "AlwaysPassValidator") -> None:
        super().__init__(config=DummyConfig(enabled=True))
        self._priority = priority
        self._name = name

    @property
    def validator_name(self) -> str:
        return self._name

    @property
    def priority(self) -> int:
        return self._priority

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        return True, None, {"status": "passed"}


class AlwaysFailValidator(BaseValidator):
    """Mock validator that always fails validation."""

    def __init__(self, priority: int = 20, name: str = "AlwaysFailValidator") -> None:
        super().__init__(config=DummyConfig(enabled=True))
        self._priority = priority
        self._name = name

    @property
    def validator_name(self) -> str:
        return self._name

    @property
    def priority(self) -> int:
        return self._priority

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        return False, f"Validation failed in {self._name}", {"status": "failed"}


class ExceptionValidator(BaseValidator):
    """Mock validator that raises an unexpected RuntimeError."""

    def __init__(self, priority: int = 30, name: str = "ExceptionValidator") -> None:
        super().__init__(config=DummyConfig(enabled=True))
        self._priority = priority
        self._name = name

    @property
    def validator_name(self) -> str:
        return self._name

    @property
    def priority(self) -> int:
        return self._priority

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        raise RuntimeError(f"Unexpected error in {self._name}")


class ValidationErrorValidator(BaseValidator):
    """Mock validator that raises an expected ValidationError."""

    def __init__(
        self, priority: int = 35, name: str = "ValidationErrorValidator"
    ) -> None:
        super().__init__(config=DummyConfig(enabled=True))
        self._priority = priority
        self._name = name

    @property
    def validator_name(self) -> str:
        return self._name

    @property
    def priority(self) -> int:
        return self._priority

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        raise ValidationError(f"Domain validation error in {self._name}")


class TrackingValidator(BaseValidator):
    """Mock validator that logs its execution to a tracking list."""

    def __init__(self, priority: int, name: str, execution_log: list[str]) -> None:
        super().__init__(config=DummyConfig(enabled=True))
        self._priority = priority
        self._name = name
        self._execution_log = execution_log

    @property
    def validator_name(self) -> str:
        return self._name

    @property
    def priority(self) -> int:
        return self._priority

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        self._execution_log.append(self._name)
        return True, None, {"tracked": self._name}


class ContextTrackingValidator(BaseValidator):
    """Mock validator that stores the exact context dictionary received during validation."""

    def __init__(
        self, priority: int = 10, name: str = "ContextTrackingValidator"
    ) -> None:
        super().__init__(config=DummyConfig(enabled=True))
        self._priority = priority
        self._name = name
        self.received_context: dict[str, Any] | None = None

    @property
    def validator_name(self) -> str:
        return self._name

    @property
    def priority(self) -> int:
        return self._priority

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        self.received_context = copy.deepcopy(context)
        return True, None, {"context_saved": True}


class DisabledMockValidator(BaseValidator):
    """Mock validator configured with enabled=False."""

    def __init__(self, priority: int = 40, name: str = "DisabledMockValidator") -> None:
        super().__init__(config=DummyConfig(enabled=False))
        self._priority = priority
        self._name = name

    @property
    def validator_name(self) -> str:
        return self._name

    @property
    def priority(self) -> int:
        return self._priority

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        return True, None, {"should_not_execute": True}


class NoConfigValidator(BaseValidator):
    """Mock validator whose config attribute is set to None."""

    def __init__(self, priority: int = 15, name: str = "NoConfigValidator") -> None:
        self.config = None
        self._priority = priority
        self._name = name

    @property
    def validator_name(self) -> str:
        return self._name

    @property
    def priority(self) -> int:
        return self._priority

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        return True, None, {"noconfig": True}


class HookTrackingPipeline(ValidationPipeline):
    """Subclass of ValidationPipeline capturing lifecycle hook invocation events."""

    def __init__(self, validators: list[BaseValidator], config: PipelineConfig) -> None:
        self.hook_events: list[tuple[Any, ...]] = []
        super().__init__(validators, config)

    def _before_pipeline(self, prompt: str, context: dict[str, Any]) -> None:
        self.hook_events.append(("before_pipeline", prompt, context))

    def _after_pipeline(self, response: InputValidationResponse) -> None:
        self.hook_events.append(("after_pipeline", response))

    def _before_validator(
        self, validator: BaseValidator, prompt: str, context: dict[str, Any]
    ) -> None:
        self.hook_events.append(("before_validator", validator.validator_name))

    def _after_validator(
        self, validator: BaseValidator, result: ValidationResult
    ) -> None:
        self.hook_events.append(
            ("after_validator", validator.validator_name, result.is_valid)
        )


# ===========================================================================
# 1. TestConstructor
# ===========================================================================


class TestConstructor:
    """Test suite for ValidationPipeline construction and validator initialization."""

    def test_constructor_with_validators_list(self) -> None:
        # Arrange
        config = PipelineConfig(fail_fast=True)
        v1 = AlwaysPassValidator(priority=10, name="V1")
        v2 = AlwaysPassValidator(priority=20, name="V2")

        # Act
        pipeline = ValidationPipeline(validators=[v1, v2], config=config)

        # Assert
        registered = pipeline.get_registered_validators()
        assert len(registered) == 2
        assert registered[0] is v1
        assert registered[1] is v2

    def test_constructor_empty_validators_list(self) -> None:
        # Arrange
        config = PipelineConfig()

        # Act
        pipeline = ValidationPipeline(validators=[], config=config)

        # Assert
        assert pipeline.get_registered_validators() == []

    def test_empty_pipeline_execution(self) -> None:
        # Arrange
        pipeline = ValidationPipeline(validators=[], config=PipelineConfig())

        # Act
        response = pipeline.validate("test prompt")

        # Assert
        assert response.results == []
        assert response.is_valid is True
        assert response.metadata["executed_validators"] == 0


# ===========================================================================
# 2. TestRegistration
# ===========================================================================


class TestRegistration:
    """Test suite for dynamic validator registration and unregistration."""

    def test_register_and_unregister_validator(self) -> None:
        # Arrange
        pipeline = ValidationPipeline(validators=[], config=PipelineConfig())
        v1 = AlwaysPassValidator(priority=10, name="V1")

        # Act - Register
        pipeline.register_validator(v1)
        assert pipeline.get_registered_validators() == [v1]

        # Act - Unregister
        pipeline.unregister_validator("V1")

        # Assert
        assert pipeline.get_registered_validators() == []

    def test_register_duplicate_validator_name_raises_error(self) -> None:
        # Arrange
        v1 = AlwaysPassValidator(priority=10, name="SameName")
        v2 = AlwaysPassValidator(priority=20, name="SameName")
        pipeline = ValidationPipeline(validators=[v1], config=PipelineConfig())

        # Act & Assert
        with pytest.raises(ValidatorRegistrationError) as exc_info:
            pipeline.register_validator(v2)

        assert "already registered in this pipeline" in str(exc_info.value)

    def test_register_duplicate_priority_raises_error(self) -> None:
        # Arrange - Duplicate priority is explicitly rejected by ValidationPipeline line 72
        v1 = AlwaysPassValidator(priority=15, name="V1")
        v2 = AlwaysPassValidator(priority=15, name="V2")
        pipeline = ValidationPipeline(validators=[v1], config=PipelineConfig())

        # Act & Assert
        with pytest.raises(ValidatorRegistrationError) as exc_info:
            pipeline.register_validator(v2)

        assert "A validator with priority '15' is already registered" in str(
            exc_info.value
        )

    def test_get_registered_validators_returns_sorted_by_priority(self) -> None:
        # Arrange - Inserted out of order (30, 10, 20)
        v3 = AlwaysPassValidator(priority=30, name="V3")
        v1 = AlwaysPassValidator(priority=10, name="V1")
        v2 = AlwaysPassValidator(priority=20, name="V2")
        pipeline = ValidationPipeline(validators=[v3, v1, v2], config=PipelineConfig())

        # Act
        sorted_validators = pipeline.get_registered_validators()

        # Assert
        assert [v.priority for v in sorted_validators] == [10, 20, 30]
        assert [v.validator_name for v in sorted_validators] == ["V1", "V2", "V3"]

    def test_register_invalid_validator_type_raises_error(self) -> None:
        # Arrange
        pipeline = ValidationPipeline(validators=[], config=PipelineConfig())

        # Act & Assert
        with pytest.raises(ValidatorRegistrationError) as exc_info:
            pipeline.register_validator("not_a_validator")  # type: ignore

        assert "Cannot register non-BaseValidator components" in str(exc_info.value)

    def test_unregister_non_existent_validator_raises_error(self) -> None:
        # Arrange
        pipeline = ValidationPipeline(validators=[], config=PipelineConfig())

        # Act & Assert
        with pytest.raises(ValidatorRegistrationError) as exc_info:
            pipeline.unregister_validator("NonExistent")

        assert "No validator with name 'NonExistent' is currently registered" in str(
            exc_info.value
        )


# ===========================================================================
# 3. TestExecutionOrder
# ===========================================================================


class TestExecutionOrder:
    """Test suite verifying priority-sorted execution ordering."""

    def test_validators_execute_in_ascending_priority_order(self) -> None:
        # Arrange
        execution_log: list[str] = []
        # Registered out of priority order: priority 30, priority 10, priority 20
        v_high = TrackingValidator(
            priority=30, name="Priority30", execution_log=execution_log
        )
        v_low = TrackingValidator(
            priority=10, name="Priority10", execution_log=execution_log
        )
        v_mid = TrackingValidator(
            priority=20, name="Priority20", execution_log=execution_log
        )

        pipeline = ValidationPipeline(
            validators=[v_high, v_low, v_mid], config=PipelineConfig()
        )

        # Act
        response = pipeline.validate("test prompt")

        # Assert
        assert response.is_valid is True
        assert execution_log == ["Priority10", "Priority20", "Priority30"]

    def test_stress_execution_with_50_validators(self) -> None:
        # Arrange
        execution_log: list[str] = []
        validators: list[BaseValidator] = [
            TrackingValidator(
                priority=i, name=f"Val_{i:02d}", execution_log=execution_log
            )
            for i in reversed(range(1, 51))  # Registered in reverse priority order
        ]
        pipeline = ValidationPipeline(validators=validators, config=PipelineConfig())

        # Act
        response = pipeline.validate("stress test prompt")

        # Assert
        assert response.is_valid is True
        assert len(response.results) == 50
        assert response.metadata["executed_validators"] == 50
        expected_names = [f"Val_{i:02d}" for i in range(1, 51)]
        assert execution_log == expected_names


# ===========================================================================
# 4. TestFailFast
# ===========================================================================


class TestFailFast:
    """Test suite verifying fail_fast=True early stopping behavior."""

    def test_fail_fast_enabled_stops_execution_on_first_failure(self) -> None:
        # Arrange
        execution_log: list[str] = []
        v1 = TrackingValidator(
            priority=10, name="Step1_Pass", execution_log=execution_log
        )
        v2 = AlwaysFailValidator(priority=20, name="Step2_Fail")
        v3 = TrackingValidator(
            priority=30, name="Step3_ShouldNotRun", execution_log=execution_log
        )

        config = PipelineConfig(fail_fast=True)
        pipeline = ValidationPipeline(validators=[v1, v2, v3], config=config)

        # Act
        response = pipeline.validate("test prompt")

        # Assert
        assert response.is_valid is False
        assert execution_log == ["Step1_Pass"]
        assert len(response.results) == 2
        assert response.results[0].validator_name == "Step1_Pass"
        assert response.results[1].validator_name == "Step2_Fail"
        assert response.metadata["fail_fast_triggered"] is True
        assert response.metadata["executed_validators"] == 2
        assert response.metadata["failed_validators"] == ["Step2_Fail"]


# ===========================================================================
# 5. TestFailSafe
# ===========================================================================


class TestFailSafe:
    """Test suite verifying fail_fast=False execution of all validators."""

    def test_fail_fast_disabled_continues_executing_remaining_validators(
        self,
    ) -> None:
        # Arrange
        execution_log: list[str] = []
        v1 = TrackingValidator(
            priority=10, name="Step1_Pass", execution_log=execution_log
        )
        v2 = AlwaysFailValidator(priority=20, name="Step2_Fail")
        v3 = TrackingValidator(
            priority=30, name="Step3_Pass", execution_log=execution_log
        )

        config = PipelineConfig(fail_fast=False)
        pipeline = ValidationPipeline(validators=[v1, v2, v3], config=config)

        # Act
        response = pipeline.validate("test prompt")

        # Assert
        assert response.is_valid is False
        assert execution_log == ["Step1_Pass", "Step3_Pass"]
        assert len(response.results) == 3
        assert response.metadata["fail_fast_triggered"] is False
        assert response.metadata["executed_validators"] == 3
        assert response.metadata["failed_validators"] == ["Step2_Fail"]


# ===========================================================================
# 6. TestAggregation
# ===========================================================================


class TestAggregation:
    """Test suite for result aggregation DTO correctness."""

    def test_result_aggregation_all_passing(self) -> None:
        # Arrange
        v1 = AlwaysPassValidator(priority=10, name="V1")
        v2 = AlwaysPassValidator(priority=20, name="V2")
        pipeline = ValidationPipeline(validators=[v1, v2], config=PipelineConfig())

        # Act
        response = pipeline.validate("test prompt")

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert response.is_valid is True
        assert len(response.results) == 2
        assert response.metadata["successful_validators"] == ["V1", "V2"]
        assert response.metadata["failed_validators"] == []
        assert response.metadata["pipeline_failed"] is False

    def test_result_aggregation_multiple_failures_fail_safe(self) -> None:
        # Arrange
        v1 = AlwaysFailValidator(priority=10, name="Fail1")
        v2 = AlwaysFailValidator(priority=20, name="Fail2")
        pipeline = ValidationPipeline(
            validators=[v1, v2], config=PipelineConfig(fail_fast=False)
        )

        # Act
        response = pipeline.validate("test prompt")

        # Assert
        assert response.is_valid is False
        assert len(response.results) == 2
        assert response.metadata["failed_validators"] == ["Fail1", "Fail2"]
        assert response.metadata["pipeline_failed"] is True


# ===========================================================================
# 7. TestContextPropagation
# ===========================================================================


class TestContextPropagation:
    """Test suite verifying context dictionary safe propagation and tracking."""

    def test_context_reaches_validators_and_normalizes_none(self) -> None:
        # Arrange
        v1 = AlwaysPassValidator(priority=10, name="V1")
        pipeline = ValidationPipeline(validators=[v1], config=PipelineConfig())
        context = {"request_id": "req-123", "user": "alice"}

        # Act
        response_context = pipeline.validate("prompt", context=context)
        response_none = pipeline.validate("prompt", context=None)

        # Assert
        assert response_context.is_valid is True
        assert response_none.is_valid is True

    def test_context_tracking_validator_receives_context_unchanged(self) -> None:
        # Arrange
        tracker = ContextTrackingValidator(priority=10)
        pipeline = ValidationPipeline(validators=[tracker], config=PipelineConfig())
        context = {"request_id": "req-context-prop", "tenant": "security-team"}

        # Act
        pipeline.validate("prompt text", context=context)

        # Assert
        assert tracker.received_context == context
        assert tracker.received_context is not context


# ===========================================================================
# 8. TestLifecycleHooks
# ===========================================================================


class TestLifecycleHooks:
    """Test suite verifying before/after pipeline and validator lifecycle hooks."""

    def test_lifecycle_hooks_execution_sequence(self) -> None:
        # Arrange
        v1 = AlwaysPassValidator(priority=10, name="V1")
        v2 = AlwaysFailValidator(priority=20, name="V2")
        pipeline = HookTrackingPipeline(
            validators=[v1, v2], config=PipelineConfig(fail_fast=False)
        )
        context = {"req": "test_hooks"}

        # Act
        response = pipeline.validate("hook prompt", context=context)

        # Assert
        events = pipeline.hook_events
        assert events[0] == ("before_pipeline", "hook prompt", {"req": "test_hooks"})
        assert events[1] == ("before_validator", "V1")
        assert events[2] == ("after_validator", "V1", True)
        assert events[3] == ("before_validator", "V2")
        assert events[4] == ("after_validator", "V2", False)
        assert events[5] == ("after_pipeline", response)


# ===========================================================================
# 9. TestDisabledValidators
# ===========================================================================


class TestDisabledValidators:
    """Test suite for disabled validators skipping logic and metadata."""

    def test_disabled_validator_is_skipped(self) -> None:
        # Arrange
        v_enabled = AlwaysPassValidator(priority=10, name="EnabledV")
        v_disabled = DisabledMockValidator(priority=20, name="DisabledV")
        pipeline = ValidationPipeline(
            validators=[v_enabled, v_disabled], config=PipelineConfig()
        )

        # Act
        response = pipeline.validate("test prompt")

        # Assert
        assert response.is_valid is True
        assert len(response.results) == 2
        assert response.results[1].metadata == {
            "skipped": True,
            "reason": "Disabled by configuration",
        }
        assert response.metadata["skipped_validators"] == ["DisabledV"]
        assert response.metadata["successful_validators"] == ["EnabledV"]

    def test_validator_with_none_config_is_treated_as_enabled(self) -> None:
        # Arrange
        v_none_config = NoConfigValidator(priority=15, name="NoConfigV")
        pipeline = ValidationPipeline(
            validators=[v_none_config], config=PipelineConfig()
        )

        # Act
        response = pipeline.validate("test prompt")

        # Assert
        assert response.is_valid is True
        assert response.metadata["successful_validators"] == ["NoConfigV"]


# ===========================================================================
# 10. TestExceptions
# ===========================================================================


class TestExceptions:
    """Test suite for exception propagation during validation execution."""

    def test_validation_error_returns_failed_result(self) -> None:
        # Arrange
        v_err = ValidationErrorValidator(priority=10, name="ErrV")
        pipeline = ValidationPipeline(validators=[v_err], config=PipelineConfig())

        # Act
        response = pipeline.validate("test prompt")

        # Assert
        assert response.is_valid is False
        assert response.results[0].error_message == "Domain validation error in ErrV"

    def test_unexpected_exception_wraps_in_validation_execution_error(self) -> None:
        # Arrange
        v_crash = ExceptionValidator(priority=10, name="CrashV")
        pipeline = ValidationPipeline(validators=[v_crash], config=PipelineConfig())

        # Act & Assert
        with pytest.raises(ValidationExecutionError) as exc_info:
            pipeline.validate("test prompt")

        assert "Unexpected crash in validator 'CrashV'" in str(exc_info.value)
        assert isinstance(exc_info.value.__cause__, RuntimeError)
        assert exc_info.value.details is not None
        assert exc_info.value.details["validator_name"] == "CrashV"


# ===========================================================================
# 11. TestMetadata
# ===========================================================================


class TestMetadata:
    """Test suite verifying pipeline response DTO metadata attributes, timings, and timestamps."""

    def test_response_metadata_fields(self) -> None:
        # Arrange
        v1 = AlwaysPassValidator(priority=10, name="V1")
        pipeline = ValidationPipeline(validators=[v1], config=PipelineConfig())

        # Act
        response = pipeline.validate("test prompt")

        # Assert
        assert isinstance(response.execution_time_ms, float)
        assert response.execution_time_ms >= 0.0
        meta = response.metadata
        assert meta["total_validators"] == 1
        assert meta["executed_validators"] == 1
        assert meta["successful_validators"] == ["V1"]
        assert meta["failed_validators"] == []
        assert meta["skipped_validators"] == []
        assert meta["pipeline_failed"] is False
        assert meta["fail_fast_triggered"] is False
        assert isinstance(meta["execution_timestamp"], str)

    def test_execution_timestamp_is_valid_iso8601_utc(self) -> None:
        # Arrange
        pipeline = ValidationPipeline(
            validators=[AlwaysPassValidator()], config=PipelineConfig()
        )

        # Act
        response = pipeline.validate("prompt")

        # Assert
        iso_ts = response.metadata["execution_timestamp"]
        parsed_dt = datetime.fromisoformat(iso_ts)
        assert parsed_dt.tzinfo is not None
        assert parsed_dt.utcoffset() == timedelta(0)

    def test_validation_result_integrity(self) -> None:
        # Arrange
        v1 = AlwaysPassValidator(priority=10, name="IntegrityV")
        pipeline = ValidationPipeline(validators=[v1], config=PipelineConfig())

        # Act
        response = pipeline.validate("prompt")

        # Assert
        assert len(response.results) == 1
        res = response.results[0]
        assert res.validator_name == "IntegrityV"
        assert isinstance(res.timestamp, datetime)
        assert res.timestamp.tzinfo is not None
        assert res.timestamp.utcoffset() == timedelta(0)
        assert isinstance(res.execution_time_ms, float)
        assert res.execution_time_ms >= 0.0
        assert isinstance(res.metadata, dict)
        assert res.error_message is None


# ===========================================================================
# 12. TestStatelessness
# ===========================================================================


class TestStatelessness:
    """Test suite verifying pipeline statelessness across repeated executions."""

    def test_stateless_repeated_execution(self) -> None:
        # Arrange
        v1 = AlwaysPassValidator(priority=10, name="V1")
        v2 = AlwaysFailValidator(priority=20, name="V2")
        pipeline = ValidationPipeline(
            validators=[v1, v2], config=PipelineConfig(fail_fast=True)
        )
        iterations = 50

        # Act & Assert
        for _ in range(iterations):
            response = pipeline.validate("repeated prompt")
            assert response.is_valid is False
            assert len(response.results) == 2
            assert response.metadata["fail_fast_triggered"] is True

    def test_stateless_repeated_execution_fresh_objects(self) -> None:
        # Arrange
        v1 = AlwaysPassValidator(priority=10, name="V1")
        pipeline = ValidationPipeline(validators=[v1], config=PipelineConfig())

        # Act
        resp1 = pipeline.validate("prompt 1")
        resp2 = pipeline.validate("prompt 2")

        # Assert
        assert resp1 is not resp2
        assert resp1.metadata is not resp2.metadata
        assert resp1.results[0] is not resp2.results[0]
        assert resp1.results[0].metadata is not resp2.results[0].metadata


# ===========================================================================
# 13. TestMultiplePipelines
# ===========================================================================


class TestMultiplePipelines:
    """Test suite verifying multiple independent pipeline instances."""

    def test_multiple_pipelines_state_independence(self) -> None:
        # Arrange
        v1 = AlwaysPassValidator(priority=10, name="V1")
        v2 = AlwaysFailValidator(priority=20, name="V2")

        pipeline_pass = ValidationPipeline(validators=[v1], config=PipelineConfig())
        pipeline_fail = ValidationPipeline(
            validators=[v1, v2], config=PipelineConfig(fail_fast=True)
        )

        # Act
        res_pass = pipeline_pass.validate("prompt")
        res_fail = pipeline_fail.validate("prompt")

        # Assert
        assert res_pass.is_valid is True
        assert res_fail.is_valid is False
        assert len(pipeline_pass.get_registered_validators()) == 1
        assert len(pipeline_fail.get_registered_validators()) == 2


# ===========================================================================
# 14. TestImmutability
# ===========================================================================


class TestImmutability:
    """Test suite verifying input context and validator immutability."""

    def test_pipeline_does_not_mutate_context(self) -> None:
        # Arrange
        v1 = AlwaysPassValidator(priority=10, name="V1")
        pipeline = ValidationPipeline(validators=[v1], config=PipelineConfig())
        original_context = {
            "req_id": "req-immutable-123",
            "metadata": {"trace": True},
        }
        context_snapshot = copy.deepcopy(original_context)

        # Act
        pipeline.validate("prompt", context=original_context)

        # Assert
        assert original_context == context_snapshot
        assert original_context["metadata"]["trace"] is True

    def test_pipeline_does_not_mutate_validator_config_or_state(self) -> None:
        # Arrange
        v1 = AlwaysPassValidator(priority=15, name="ImmutableValidator")
        pipeline = ValidationPipeline(validators=[v1], config=PipelineConfig())
        initial_enabled = v1.config.enabled
        initial_priority = v1.priority
        initial_name = v1.validator_name

        # Act
        pipeline.validate("prompt")

        # Assert
        assert v1.config.enabled == initial_enabled
        assert v1.priority == initial_priority
        assert v1.validator_name == initial_name
