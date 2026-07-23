"""
Enterprise-grade unit test suite for InputValidator facade component.

Validates facade construction, configuration injection, pipeline injection, validator list forwarding,
precedence of injected pipelines over validators lists, argument type checking, context normalization & non-aliasing,
delegation to ValidationPipeline APIs, health diagnostic report generation, return type contracts,
exception propagation, prompt & context immutability, stateless execution with fresh object instantiation,
and multi-instance independence.
"""

import copy
from datetime import datetime, timezone
from typing import Any

import pytest

from input_validator.config import InputValidatorConfig, PipelineConfig
from input_validator.exceptions import (
    ValidationError,
    ValidationExecutionError,
)
from input_validator.input_validator import FRAMEWORK_VERSION, InputValidator
from input_validator.models import InputValidationResponse, ValidationResult
from input_validator.pipeline import ValidationPipeline
from input_validator.validators.base_validator import BaseValidator

# ===========================================================================
# Lightweight Mocks for Facade Delegation Testing
# ===========================================================================


class MockValidatorForFacade(BaseValidator):
    """Lightweight mock validator for testing facade delegation."""

    def __init__(
        self, priority: int = 10, name: str = "MockValidatorForFacade"
    ) -> None:
        super().__init__(config=None)
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
        return True, None, {"mock": True}


class MockPipeline:
    """Mock pipeline recording calls to validate delegation behavior."""

    def __init__(self) -> None:
        self.registered_validators_list: list[BaseValidator] = []
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.should_raise: Exception | None = None
        self.canned_response: InputValidationResponse = InputValidationResponse(
            is_valid=True,
            results=[
                ValidationResult(
                    validator_name="MockValidator",
                    is_valid=True,
                    error_message=None,
                    execution_time_ms=1.2,
                    timestamp=datetime.now(timezone.utc),
                    metadata={"canned": True},
                )
            ],
            execution_time_ms=2.5,
            metadata={"mock_pipeline": True},
        )

    def validate(
        self, prompt: str, context: dict[str, Any] | None = None
    ) -> InputValidationResponse:
        self.calls.append(("validate", (prompt, context), {}))
        if self.should_raise:
            raise self.should_raise
        return self.canned_response

    def register_validator(self, validator: BaseValidator) -> None:
        self.calls.append(("register_validator", (validator,), {}))
        self.registered_validators_list.append(validator)

    def unregister_validator(self, validator_name: str) -> None:
        self.calls.append(("unregister_validator", (validator_name,), {}))
        self.registered_validators_list = [
            v
            for v in self.registered_validators_list
            if v.validator_name != validator_name
        ]

    def get_registered_validators(self) -> list[BaseValidator]:
        self.calls.append(("get_registered_validators", (), {}))
        return self.registered_validators_list


# ===========================================================================
# 1. TestConstructor
# ===========================================================================


class TestConstructor:
    """Test suite for InputValidator facade initialization and properties."""

    def test_default_constructor(self) -> None:
        # Arrange & Act
        validator = InputValidator()

        # Assert
        assert validator.version == FRAMEWORK_VERSION
        assert isinstance(validator.pipeline, ValidationPipeline)
        assert validator.registered_validators() == []

    def test_constructor_with_zero_validators(self) -> None:
        # Arrange & Act
        validator = InputValidator(validators=[])

        # Assert
        assert validator.registered_validators() == []
        assert len(validator.registered_validators()) == 0

    def test_constructor_with_custom_configuration(self) -> None:
        # Arrange
        config = InputValidatorConfig(pipeline=PipelineConfig(fail_fast=False))

        # Act
        validator = InputValidator(config=config)

        # Assert
        assert validator.pipeline._config.fail_fast is False

    def test_constructor_with_custom_pipeline_injection(self) -> None:
        # Arrange
        mock_pipeline = MockPipeline()

        # Act
        validator = InputValidator(pipeline=mock_pipeline)  # type: ignore

        # Assert
        assert validator.pipeline is mock_pipeline

    def test_constructor_with_validators_list_injection(self) -> None:
        # Arrange
        v1 = MockValidatorForFacade(priority=10, name="V1")
        v2 = MockValidatorForFacade(priority=20, name="V2")

        # Act
        validator = InputValidator(validators=[v1, v2])

        # Assert
        registered = validator.registered_validators()
        assert len(registered) == 2
        assert registered[0].validator_name == "V1"
        assert registered[1].validator_name == "V2"

    def test_pipeline_and_validators_both_supplied_pipeline_takes_precedence(
        self,
    ) -> None:
        # Arrange
        mock_pipeline = MockPipeline()
        ignored_v1 = MockValidatorForFacade(priority=10, name="IgnoredV1")
        ignored_v2 = MockValidatorForFacade(priority=20, name="IgnoredV2")

        # Act - Supply both pipeline and validators list
        validator = InputValidator(
            pipeline=mock_pipeline, validators=[ignored_v1, ignored_v2]  # type: ignore
        )

        # Assert - The externally injected pipeline is used directly
        assert validator.pipeline is mock_pipeline
        assert (
            validator.registered_validators()
            == mock_pipeline.registered_validators_list
        )
        assert ignored_v1 not in mock_pipeline.registered_validators_list

    def test_health_diagnostic_report(self) -> None:
        # Arrange
        v1 = MockValidatorForFacade(priority=10, name="HealthV")
        validator = InputValidator(validators=[v1])

        # Act
        health_info = validator.health()

        # Assert
        assert isinstance(health_info["framework_version"], str)
        assert health_info["framework_version"] == validator.version
        assert health_info["registered_validators"] == ["HealthV"]
        assert health_info["pipeline_ready"] is True
        assert health_info["configuration_loaded"] is True


# ===========================================================================
# 2. TestValidate
# ===========================================================================


class TestValidate:
    """Test suite verifying validate() method execution and parameter forwarding."""

    def test_validate_delegates_to_pipeline(self) -> None:
        # Arrange
        mock_pipeline = MockPipeline()
        validator = InputValidator(pipeline=mock_pipeline)  # type: ignore
        prompt = "Hello AI SecOps"
        context = {"request_id": "req-facade-1"}

        # Act
        response = validator.validate(prompt, context)

        # Assert
        assert response is mock_pipeline.canned_response
        assert len(mock_pipeline.calls) == 1
        call_name, args, kwargs = mock_pipeline.calls[0]
        assert call_name == "validate"
        assert args[0] == "Hello AI SecOps"
        assert args[1] == {"request_id": "req-facade-1"}


# ===========================================================================
# 3. TestDelegation
# ===========================================================================


class TestDelegation:
    """Test suite verifying validator management delegation methods."""

    def test_register_validator_delegates_to_pipeline(self) -> None:
        # Arrange
        mock_pipeline = MockPipeline()
        validator = InputValidator(pipeline=mock_pipeline)  # type: ignore
        mock_v = MockValidatorForFacade()

        # Act
        validator.register_validator(mock_v)

        # Assert
        assert ("register_validator", (mock_v,), {}) in mock_pipeline.calls

    def test_unregister_validator_delegates_to_pipeline(self) -> None:
        # Arrange
        mock_pipeline = MockPipeline()
        validator = InputValidator(pipeline=mock_pipeline)  # type: ignore

        # Act
        validator.unregister_validator("MockValidatorForFacade")

        # Assert
        assert (
            "unregister_validator",
            ("MockValidatorForFacade",),
            {},
        ) in mock_pipeline.calls

    def test_registered_validators_delegates_to_pipeline(self) -> None:
        # Arrange
        mock_pipeline = MockPipeline()
        validator = InputValidator(pipeline=mock_pipeline)  # type: ignore

        # Act
        res = validator.registered_validators()

        # Assert
        assert ("get_registered_validators", (), {}) in mock_pipeline.calls
        assert res == mock_pipeline.registered_validators_list


# ===========================================================================
# 4. TestConfiguration
# ===========================================================================


class TestConfiguration:
    """Test suite verifying configuration injection into InputValidator."""

    def test_configuration_stored_and_passed_to_pipeline(self) -> None:
        # Arrange
        custom_config = InputValidatorConfig(
            pipeline=PipelineConfig(fail_fast=False, timeout_ms=5000)
        )

        # Act
        validator = InputValidator(config=custom_config)

        # Assert
        assert validator._config is custom_config
        assert validator.pipeline._config.fail_fast is False
        assert validator.pipeline._config.timeout_ms == 5000


# ===========================================================================
# 5. TestPipelineInjection
# ===========================================================================


class TestPipelineInjection:
    """Test suite verifying external ValidationPipeline injection."""

    def test_externally_supplied_pipeline_used_directly(self) -> None:
        # Arrange
        mock_pipeline = MockPipeline()

        # Act
        validator = InputValidator(pipeline=mock_pipeline)  # type: ignore

        # Assert
        assert validator.pipeline is mock_pipeline
        assert validator.pipeline is not None


# ===========================================================================
# 6. TestArgumentValidation
# ===========================================================================


class TestArgumentValidation:
    """Test suite verifying public API argument validation and bounds."""

    @pytest.mark.parametrize(
        "valid_prompt, description",
        [
            ("valid prompt string", "standard text"),
            ("", "empty string"),
            ("   ", "whitespace string"),
            ("漢字 prompt 🚀", "unicode with emoji"),
            ("line 1\nline 2\nline 3", "multiline string"),
            ("x" * 100_000, "large prompt string"),
        ],
    )
    def test_valid_prompts_accepted(self, valid_prompt: str, description: str) -> None:
        # Arrange
        mock_pipeline = MockPipeline()
        validator = InputValidator(pipeline=mock_pipeline)  # type: ignore

        # Act
        response = validator.validate(valid_prompt)

        # Assert
        assert response is mock_pipeline.canned_response

    @pytest.mark.parametrize("invalid_prompt", [None, 123, 4.56, [], {}])
    def test_non_string_prompt_raises_validation_error(
        self, invalid_prompt: Any
    ) -> None:
        # Arrange
        validator = InputValidator()

        # Act & Assert
        with pytest.raises(ValidationError) as exc_info:
            validator.validate(invalid_prompt)

        assert "Prompt parameter must be a string" in str(exc_info.value)


# ===========================================================================
# 7. TestContextNormalization
# ===========================================================================


class TestContextNormalization:
    """Test suite verifying context normalization and non-aliasing."""

    def test_context_none_normalizes_to_empty_dict(self) -> None:
        # Arrange
        mock_pipeline = MockPipeline()
        validator = InputValidator(pipeline=mock_pipeline)  # type: ignore

        # Act
        validator.validate("prompt", context=None)

        # Assert
        _, args, _ = mock_pipeline.calls[0]
        assert args[1] == {}

    def test_dictionary_context_passed_as_dictionary_new_object_instance(self) -> None:
        # Arrange
        mock_pipeline = MockPipeline()
        validator = InputValidator(pipeline=mock_pipeline)  # type: ignore
        ctx = {"key": "value", "session": "s1"}

        # Act
        validator.validate("prompt", context=ctx)

        # Assert
        _, args, _ = mock_pipeline.calls[0]
        normalized_ctx = args[1]
        assert normalized_ctx == ctx
        assert normalized_ctx is not ctx


# ===========================================================================
# 8. TestReturnTypes
# ===========================================================================


class TestReturnTypes:
    """Test suite verifying validate() return DTO types."""

    def test_validate_returns_input_validation_response(self) -> None:
        # Arrange
        v1 = MockValidatorForFacade()
        validator = InputValidator(validators=[v1])

        # Act
        response = validator.validate("test prompt")

        # Assert
        assert isinstance(response, InputValidationResponse)
        assert isinstance(response.is_valid, bool)
        assert isinstance(response.execution_time_ms, float)
        assert isinstance(response.metadata, dict)


# ===========================================================================
# 9. TestExceptions
# ===========================================================================


class TestExceptions:
    """Test suite verifying exception propagation from pipeline without absorption."""

    def test_validation_error_propagates_uncaught(self) -> None:
        # Arrange
        mock_pipeline = MockPipeline()
        mock_pipeline.should_raise = ValidationError("Pipeline validation error")
        validator = InputValidator(pipeline=mock_pipeline)  # type: ignore

        # Act & Assert
        with pytest.raises(ValidationError) as exc_info:
            validator.validate("prompt")

        assert "Pipeline validation error" in str(exc_info.value)

    def test_validation_execution_error_propagates_uncaught(self) -> None:
        # Arrange
        mock_pipeline = MockPipeline()
        mock_pipeline.should_raise = ValidationExecutionError("Execution failed")
        validator = InputValidator(pipeline=mock_pipeline)  # type: ignore

        # Act & Assert
        with pytest.raises(ValidationExecutionError) as exc_info:
            validator.validate("prompt")

        assert "Execution failed" in str(exc_info.value)


# ===========================================================================
# 10. TestImmutability
# ===========================================================================


class TestImmutability:
    """Test suite verifying input prompt, context, and configuration immutability."""

    def test_validate_does_not_mutate_context_or_config(self) -> None:
        # Arrange
        config = InputValidatorConfig()
        config_snapshot = copy.deepcopy(config)
        validator = InputValidator(config=config)

        original_context = {"request_id": "req-immutable", "meta": {"trace": True}}
        context_snapshot = copy.deepcopy(original_context)

        # Act
        validator.validate("test prompt", context=original_context)

        # Assert
        assert original_context == context_snapshot
        assert validator._config == config_snapshot

    def test_validate_does_not_mutate_prompt(self) -> None:
        # Arrange
        v1 = MockValidatorForFacade()
        validator = InputValidator(validators=[v1])
        original_prompt = "immutable test prompt string"
        prompt_snapshot = str(original_prompt)

        # Act
        validator.validate(original_prompt)

        # Assert
        assert original_prompt == prompt_snapshot


# ===========================================================================
# 11. TestStatelessness
# ===========================================================================


class TestStatelessness:
    """Test suite verifying stateless repeated execution across multiple calls."""

    def test_stateless_repeated_executions(self) -> None:
        # Arrange
        v1 = MockValidatorForFacade()
        validator = InputValidator(validators=[v1])
        iterations = 50

        # Act & Assert
        for _ in range(iterations):
            response = validator.validate("repeated prompt")
            assert response.is_valid is True
            assert len(response.results) == 1

    def test_stateless_repeated_executions_fresh_objects(self) -> None:
        # Arrange
        v1 = MockValidatorForFacade()
        validator = InputValidator(validators=[v1])

        # Act
        resp1 = validator.validate("prompt 1")
        resp2 = validator.validate("prompt 2")

        # Assert
        assert resp1 is not resp2
        assert resp1.results is not resp2.results
        assert resp1.results[0] is not resp2.results[0]
        assert resp1.metadata is not resp2.metadata


# ===========================================================================
# 12. TestMultipleInstances
# ===========================================================================


class TestMultipleInstances:
    """Test suite verifying independent behavior of multiple InputValidator instances."""

    def test_multiple_input_validator_instances(self) -> None:
        # Arrange
        v1 = MockValidatorForFacade(priority=10, name="V1")
        v2 = MockValidatorForFacade(priority=20, name="V2")

        val1 = InputValidator(validators=[v1])
        val2 = InputValidator(validators=[v1, v2])

        # Act & Assert
        assert len(val1.registered_validators()) == 1
        assert len(val2.registered_validators()) == 2
        assert val1.registered_validators()[0].validator_name == "V1"
        assert val2.registered_validators()[1].validator_name == "V2"
