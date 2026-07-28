"""
Enterprise-grade unit test suite for input_validator.validators.base_validator module.

Validates the BaseValidator lifecycle, Template Method pattern execution,
pre-validation input checks, timing instrumentation, context/request_id propagation,
recoverable ValidationError handling, unexpected exception wrapping, and metadata immutability.
"""

from datetime import datetime, timezone
from typing import Any

import pytest

from input_validator.exceptions import ValidationError, ValidationExecutionError
from input_validator.models import ValidationResult
from input_validator.base_validator import BaseValidator

# ===========================================================================
# Test Doubles (Fake Validators)
# ===========================================================================


class DummyValidator(BaseValidator):
    """Fake validator that always succeeds with custom metadata."""

    @property
    def validator_name(self) -> str:
        return "dummy_validator"

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        return True, None, {"status": "passed", "rule": "dummy"}


class AlwaysPassValidator(BaseValidator):
    """Fake validator that passes with no metadata."""

    @property
    def validator_name(self) -> str:
        return "always_pass_validator"

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        return True, None, None


class AlwaysFailValidator(BaseValidator):
    """Fake validator that fails with an error message and metadata."""

    @property
    def validator_name(self) -> str:
        return "always_fail_validator"

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        return False, "Explicit validation error", {"failed_rule": "check_1"}


class AlwaysFailNoMessageValidator(BaseValidator):
    """Fake validator that fails with None for error message."""

    @property
    def validator_name(self) -> str:
        return "always_fail_no_message"

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        return False, None, None


class ValidationErrorValidator(BaseValidator):
    """Fake validator that raises a recoverable ValidationError inside _validate."""

    @property
    def validator_name(self) -> str:
        return "validation_error_validator"

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        raise ValidationError(
            message="Recoverable check failed",
            details={"step": "pre_check", "code": 400},
        )


class ExceptionValidator(BaseValidator):
    """Fake validator that raises an unexpected RuntimeError."""

    @property
    def validator_name(self) -> str:
        return "exception_validator"

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        raise RuntimeError("Unexpected database connection crash")


class ValidationExecutionErrorValidator(BaseValidator):
    """Fake validator that raises a ValidationExecutionError directly inside _validate."""

    @property
    def validator_name(self) -> str:
        return "execution_error_validator"

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        raise ValidationExecutionError(
            message="Direct execution error raised",
            details={"validator_name": "execution_error_validator"},
        )


class SuperCallingValidator(BaseValidator):
    """Fake validator that invokes super abstract methods to exercise abstract pass statements."""

    @property
    def validator_name(self) -> str:
        return "super_calling_validator"

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        return True, None, None


class LifecycleTrackingValidator(BaseValidator):
    """Fake validator that tracks lifecycle call sequence."""

    def __init__(self, config: Any) -> None:
        super().__init__(config)
        self.call_history: list[str] = []

    @property
    def validator_name(self) -> str:
        return "lifecycle_tracking_validator"

    def _validate_input(self, prompt: str) -> None:
        self.call_history.append("_validate_input")
        super()._validate_input(prompt)

    def _validate(
        self, prompt: str, context: dict[str, Any]
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        self.call_history.append("_validate")
        return True, None, {"history": list(self.call_history)}


# ===========================================================================
# 1. TestConstructor
# ===========================================================================


class TestConstructor:
    """Test suite for BaseValidator constructor and abstract class behavior."""

    def test_config_injection(self) -> None:
        # Arrange
        config_payload = {"timeout_ms": 1000, "strict_mode": True}

        # Act
        validator = DummyValidator(config=config_payload)

        # Assert
        assert validator.config == config_payload
        assert validator.config["timeout_ms"] == 1000

    def test_validator_name_property(self) -> None:
        # Arrange & Act
        validator = DummyValidator(config=None)

        # Assert
        assert validator.validator_name == "dummy_validator"

    def test_abstract_class_instantiation_raises_type_error(self) -> None:
        # Arrange, Act & Assert
        with pytest.raises(TypeError):
            BaseValidator(config=None)  # type: ignore[abstract]

    def test_super_abstract_methods_invocations(self) -> None:
        # Arrange
        validator = SuperCallingValidator(config=None)

        # Act
        result = validator.validate("Test prompt")

        # Assert
        assert validator.validator_name == "super_calling_validator"
        assert result.is_valid is True


# ===========================================================================
# 2. TestLifecycle
# ===========================================================================


class TestLifecycle:
    """Test suite for Template Method validation lifecycle execution."""

    def test_successful_validation_lifecycle(self) -> None:
        # Arrange
        validator = DummyValidator(config=None)
        prompt = "Hello, world!"
        context = {"user_id": 42}

        # Act
        result = validator.validate(prompt=prompt, context=context)

        # Assert
        assert isinstance(result, ValidationResult)
        assert result.validator_name == "dummy_validator"
        assert result.is_valid is True
        assert result.error_message is None
        assert result.execution_time_ms >= 0.0
        assert isinstance(result.timestamp, datetime)
        assert result.timestamp.tzinfo is timezone.utc
        assert result.metadata["status"] == "passed"

    def test_template_method_execution_order(self) -> None:
        # Arrange
        validator = LifecycleTrackingValidator(config=None)
        prompt = "Valid prompt"

        # Act
        result = validator.validate(prompt)

        # Assert
        assert validator.call_history == ["_validate_input", "_validate"]
        assert result.is_valid is True

    @pytest.mark.parametrize(
        "complex_prompt",
        [
            "",  # Empty prompt
            "a" * 100_000,  # Extremely long prompt
            "Hello 🌟 Safe Prompt 🚀 漢字",  # Multi-byte Unicode prompt
            "\n\t\r Special Characters \0",  # Control characters
        ],
    )
    def test_unicode_and_edge_case_prompts_lifecycle(self, complex_prompt: str) -> None:
        # Arrange
        validator = AlwaysPassValidator(config=None)

        # Act
        result = validator.validate(prompt=complex_prompt)

        # Assert
        assert result.is_valid is True
        assert result.error_message is None


# ===========================================================================
# 3. TestValidationFailures
# ===========================================================================


class TestValidationFailures:
    """Test suite for failed validation handling and recoverable error trapping."""

    def test_failed_validation_with_error_message(self) -> None:
        # Arrange
        validator = AlwaysFailValidator(config=None)
        prompt = "Test prompt"

        # Act
        result = validator.validate(prompt)

        # Assert
        assert isinstance(result, ValidationResult)
        assert result.is_valid is False
        assert result.error_message == "Explicit validation error"
        assert result.metadata["failed_rule"] == "check_1"

    def test_failed_validation_fallback_error_message(self) -> None:
        # Arrange
        validator = AlwaysFailNoMessageValidator(config=None)
        prompt = "Test prompt"

        # Act
        result = validator.validate(prompt)

        # Assert
        assert result.is_valid is False
        assert result.error_message == "Validation failed"

    def test_recoverable_validation_error_handled(self) -> None:
        # Arrange
        validator = ValidationErrorValidator(config=None)
        prompt = "Test prompt"

        # Act
        result = validator.validate(prompt)

        # Assert
        assert isinstance(result, ValidationResult)
        assert result.is_valid is False
        assert result.error_message == "Recoverable check failed"
        assert result.metadata["step"] == "pre_check"
        assert result.metadata["code"] == 400

    def test_validation_execution_error_handled_as_validation_error_subclass(
        self,
    ) -> None:
        # Arrange
        validator = ValidationExecutionErrorValidator(config=None)
        prompt = "Test prompt"

        # Act
        result = validator.validate(prompt)

        # Assert
        assert isinstance(result, ValidationResult)
        assert result.is_valid is False
        assert result.error_message == "Direct execution error raised"
        assert result.metadata["validator_name"] == "execution_error_validator"

    @pytest.mark.parametrize(
        "invalid_prompt",
        [
            None,
            123,
            45.67,
            ["invalid", "prompt"],
            {"prompt": "text"},
            True,
        ],
    )
    def test_non_string_prompt_raises_validation_error_result(
        self, invalid_prompt: Any
    ) -> None:
        # Arrange
        validator = DummyValidator(config=None)

        # Act
        result = validator.validate(prompt=invalid_prompt)

        # Assert
        assert isinstance(result, ValidationResult)
        assert result.is_valid is False
        assert "Input prompt must be a string" in (result.error_message or "")
        assert result.metadata["validator_name"] == "dummy_validator"


# ===========================================================================
# 4. TestHelperMethods
# ===========================================================================


class TestHelperMethods:
    """Test suite for individual BaseValidator helper methods."""

    def test_validate_input_valid_string(self) -> None:
        # Arrange
        validator = DummyValidator(config=None)

        # Act & Assert (should not raise)
        validator._validate_input("Valid input string")

    @pytest.mark.parametrize(
        "invalid_input",
        [None, 100, 3.14, ["list"], {"dict": 1}],
    )
    def test_validate_input_invalid_types_raise_validation_error(
        self, invalid_input: Any
    ) -> None:
        # Arrange
        validator = DummyValidator(config=None)

        # Act & Assert
        with pytest.raises(ValidationError) as exc_info:
            validator._validate_input(invalid_input)

        assert exc_info.type is ValidationError
        assert "Input prompt must be a string" in exc_info.value.message
        assert exc_info.value.details["validator_name"] == "dummy_validator"

    def test_measure_execution_time(self) -> None:
        # Arrange
        validator = DummyValidator(config=None)
        start = 100.0

        # Act
        elapsed = validator._measure_execution_time(start)

        # Assert
        assert isinstance(elapsed, float)

    def test_current_timestamp(self) -> None:
        # Arrange
        validator = DummyValidator(config=None)

        # Act
        now = validator._current_timestamp()

        # Assert
        assert isinstance(now, datetime)
        assert now.tzinfo is timezone.utc

    def test_handle_exception_wraps_unexpected_exceptions(self) -> None:
        # Arrange
        validator = DummyValidator(config=None)
        cause_exception = KeyError("missing_key")

        # Act
        wrapped = validator._handle_exception(cause_exception)

        # Assert
        assert isinstance(wrapped, ValidationExecutionError)
        assert "Unexpected crash in validator 'dummy_validator'" in str(wrapped)
        assert wrapped.details["validator_name"] == "dummy_validator"
        assert wrapped.__cause__ is cause_exception

    def test_handle_exception_returns_validation_execution_error_as_is(self) -> None:
        # Arrange
        validator = DummyValidator(config=None)
        existing_error = ValidationExecutionError("Execution crashed")

        # Act
        result_error = validator._handle_exception(existing_error)

        # Assert
        assert result_error is existing_error

    def test_build_success_result(self) -> None:
        # Arrange
        validator = DummyValidator(config=None)
        meta = {"key": "val"}
        ctx = {"request_id": "req-123"}

        # Act
        result = validator._build_success_result(
            elapsed_ms=12.5, metadata=meta, context=ctx
        )

        # Assert
        assert result.validator_name == "dummy_validator"
        assert result.is_valid is True
        assert result.error_message is None
        assert result.execution_time_ms == 12.5
        assert result.metadata["key"] == "val"
        assert result.metadata["request_id"] == "req-123"

    def test_build_failure_result(self) -> None:
        # Arrange
        validator = DummyValidator(config=None)
        meta = {"reason": "blocked"}
        ctx = {"request_id": "req-999"}

        # Act
        result = validator._build_failure_result(
            error_message="Access denied",
            elapsed_ms=5.0,
            metadata=meta,
            context=ctx,
        )

        # Assert
        assert result.validator_name == "dummy_validator"
        assert result.is_valid is False
        assert result.error_message == "Access denied"
        assert result.execution_time_ms == 5.0
        assert result.metadata["reason"] == "blocked"
        assert result.metadata["request_id"] == "req-999"


# ===========================================================================
# 5. TestExceptionHandling
# ===========================================================================


class TestExceptionHandling:
    """Test suite for unhandled exception wrapping and exception chaining."""

    def test_unexpected_exception_wrapped_in_validation_execution_error(self) -> None:
        # Arrange
        validator = ExceptionValidator(config=None)
        prompt = "Test prompt"

        # Act & Assert
        with pytest.raises(ValidationExecutionError) as exc_info:
            validator.validate(prompt)

        assert exc_info.type is ValidationExecutionError
        assert "Unexpected crash in validator 'exception_validator'" in str(
            exc_info.value
        )
        assert isinstance(exc_info.value.__cause__, RuntimeError)
        assert str(exc_info.value.__cause__) == "Unexpected database connection crash"
        assert exc_info.value.details["validator_name"] == "exception_validator"


# ===========================================================================
# 6. TestMetadata
# ===========================================================================


class TestMetadata:
    """Test suite for metadata dictionary preservation, immutability, and request_id injection."""

    def test_metadata_preserved_and_not_mutated(self) -> None:
        # Arrange
        original_meta = {"rule_name": "length_check", "value": 100}
        meta_copy = dict(original_meta)
        validator = DummyValidator(config=None)

        # Act
        result = validator.validate("Test", context={"request_id": "req-555"})

        # Assert
        assert original_meta == meta_copy
        assert "request_id" not in original_meta
        assert result.metadata["request_id"] == "req-555"
        assert result.metadata["rule"] == "dummy"

    def test_request_id_propagation_from_context(self) -> None:
        # Arrange
        validator = AlwaysPassValidator(config=None)
        context = {"request_id": "req-abcd-1234"}

        # Act
        result = validator.validate("Test", context=context)

        # Assert
        assert result.metadata["request_id"] == "req-abcd-1234"

    def test_existing_request_id_in_metadata_not_overwritten(self) -> None:
        # Arrange
        class CustomRequestIdValidator(BaseValidator):
            @property
            def validator_name(self) -> str:
                return "custom_request_id_validator"

            def _validate(
                self, prompt: str, context: dict[str, Any]
            ) -> tuple[bool, str | None, dict[str, Any] | None]:
                return True, None, {"request_id": "meta-existing-id"}

        validator = CustomRequestIdValidator(config=None)
        context = {"request_id": "ctx-override-id"}

        # Act
        result = validator.validate("Test", context=context)

        # Assert
        assert result.metadata["request_id"] == "meta-existing-id"

    def test_empty_and_none_metadata_handling(self) -> None:
        # Arrange
        validator = AlwaysPassValidator(config=None)

        # Act
        result = validator.validate("Test", context=None)

        # Assert
        assert result.metadata == {}

    def test_empty_and_none_context_handling(self) -> None:
        # Arrange
        validator = DummyValidator(config=None)

        # Act
        result_none_ctx = validator.validate("Test", context=None)
        result_empty_ctx = validator.validate("Test", context={})

        # Assert
        assert result_none_ctx.metadata["status"] == "passed"
        assert result_empty_ctx.metadata["status"] == "passed"


# ===========================================================================
# 7. TestTiming
# ===========================================================================


class TestTiming:
    """Test suite for execution timing instrumentation and UTC timestamping."""

    def test_execution_time_is_positive_float(self) -> None:
        # Arrange
        validator = DummyValidator(config=None)

        # Act
        result = validator.validate("Timing prompt")

        # Assert
        assert isinstance(result.execution_time_ms, float)
        assert result.execution_time_ms >= 0.0

    def test_timestamp_is_utc_datetime(self) -> None:
        # Arrange
        validator = DummyValidator(config=None)
        before_time = datetime.now(timezone.utc)

        # Act
        result = validator.validate("Timestamp prompt")

        # Assert
        after_time = datetime.now(timezone.utc)
        assert isinstance(result.timestamp, datetime)
        assert result.timestamp.tzinfo is timezone.utc
        assert before_time <= result.timestamp <= after_time
