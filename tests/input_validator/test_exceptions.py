"""
Enterprise-grade unit test suite for input_validator.exceptions module.

Validates exception hierarchy, ErrorCode enum mapping, constructor behavior,
recoverable flags, timezone-aware timestamping, dictionary serialization,
serialization immutability, string/representation formatting, exception chaining,
slots enforcement, and Python raising semantics.
"""

from datetime import datetime, timezone
from typing import Type

import pytest

from input_validator.exceptions import (
    CompletenessValidationError,
    ConfigurationError,
    ContextValidationError,
    EncodingValidationError,
    ErrorCode,
    FileValidationError,
    InputValidatorError,
    LanguageValidationError,
    SchemaValidationError,
    ValidationCancelledError,
    ValidationError,
    ValidationExecutionError,
    ValidationTimeoutError,
    ValidatorInitializationError,
    ValidatorRegistrationError,
)

# ===========================================================================
# 1. ErrorCode Enum Tests
# ===========================================================================


class TestErrorCode:
    """Test suite for ErrorCode enumeration members and properties."""

    def test_enum_members_exist(self) -> None:
        # Arrange & Act
        expected_codes = {
            "CONFIGURATION_ERROR",
            "VALIDATION_ERROR",
            "VALIDATION_EXECUTION_ERROR",
            "VALIDATION_TIMEOUT",
            "VALIDATION_CANCELLED",
            "VALIDATOR_NOT_REGISTERED",
            "VALIDATOR_INITIALIZATION_FAILED",
            "SCHEMA_ERROR",
            "LANGUAGE_ERROR",
            "ENCODING_ERROR",
            "FILE_ERROR",
            "CONTEXT_ERROR",
            "COMPLETENESS_ERROR",
            "UNKNOWN_ERROR",
        }

        actual_codes = {member.name for member in ErrorCode}

        # Assert
        assert actual_codes == expected_codes

    def test_enum_values_are_unique(self) -> None:
        # Arrange & Act
        values = [member.value for member in ErrorCode]

        # Assert
        assert len(values) == len(set(values))

    def test_enum_values_are_strings(self) -> None:
        # Arrange & Act & Assert
        for member in ErrorCode:
            assert isinstance(member.value, str)
            assert member.value == member.name


# ===========================================================================
# 2. InputValidatorError Base Class Tests
# ===========================================================================


class TestInputValidatorError:
    """Test suite for base InputValidatorError constructor, defaults, and slots."""

    def test_default_initialization(self) -> None:
        # Arrange & Act
        err = InputValidatorError("Base error occurred")

        # Assert
        assert err.message == "Base error occurred"
        assert err.error_code == ErrorCode.UNKNOWN_ERROR
        assert err.details == {}
        assert err.recoverable is False
        assert err.__cause__ is None
        assert isinstance(err.timestamp, datetime)

    def test_custom_initialization(self) -> None:
        # Arrange
        message = "Custom base error"
        code = ErrorCode.CONFIGURATION_ERROR
        details = {"key": "value"}
        cause = ValueError("Underlying error")
        recoverable = True

        # Act
        err = InputValidatorError(
            message=message,
            error_code=code,
            details=details,
            cause=cause,
            recoverable=recoverable,
        )

        # Assert
        assert err.message == message
        assert err.error_code == code
        assert err.details == details
        assert err.recoverable is True
        assert err.__cause__ is cause

    def test_slots_enforcement(self) -> None:
        # Arrange
        err = InputValidatorError("Slots enforcement test")

        # Act & Assert
        assert hasattr(err, "__slots__")
        assert InputValidatorError.__slots__ == (
            "message",
            "error_code",
            "details",
            "recoverable",
            "timestamp",
        )
        with pytest.raises(AttributeError):
            _ = err.undeclared_attribute  # type: ignore[attr-defined]


# ===========================================================================
# 3. Framework Exceptions Tests
# ===========================================================================


class TestFrameworkExceptions:
    """Test suite for non-recoverable framework failure exceptions."""

    @pytest.mark.parametrize(
        "exc_class, expected_error_code",
        [
            (ConfigurationError, ErrorCode.CONFIGURATION_ERROR),
            (ValidatorRegistrationError, ErrorCode.VALIDATOR_NOT_REGISTERED),
            (ValidatorInitializationError, ErrorCode.VALIDATOR_INITIALIZATION_FAILED),
        ],
    )
    def test_framework_exception_error_code_and_recoverability(
        self, exc_class: Type[InputValidatorError], expected_error_code: ErrorCode
    ) -> None:
        # Arrange & Act
        err = exc_class("Framework error")

        # Assert
        assert err.error_code == expected_error_code
        assert err.recoverable is False

    @pytest.mark.parametrize(
        "exc_class",
        [
            ConfigurationError,
            ValidatorRegistrationError,
            ValidatorInitializationError,
        ],
    )
    def test_framework_exception_inheritance(
        self, exc_class: Type[InputValidatorError]
    ) -> None:
        # Arrange & Act
        err = exc_class("Inheritance check")

        # Assert
        assert isinstance(err, InputValidatorError)
        assert issubclass(exc_class, InputValidatorError)

    @pytest.mark.parametrize(
        "exc_class",
        [
            ConfigurationError,
            ValidatorRegistrationError,
            ValidatorInitializationError,
        ],
    )
    def test_framework_exception_details_and_cause(
        self, exc_class: Type[InputValidatorError]
    ) -> None:
        # Arrange
        details = {"component": "parser"}
        cause = RuntimeError("System fault")

        # Act
        err = exc_class("Detailed error", details=details, cause=cause)

        # Assert
        assert err.details == details
        assert err.__cause__ is cause


# ===========================================================================
# 4. Validation Exceptions Tests
# ===========================================================================


class TestValidationExceptions:
    """Test suite for recoverable prompt validation failure exceptions."""

    @pytest.mark.parametrize(
        "exc_class, expected_error_code",
        [
            (ValidationError, ErrorCode.VALIDATION_ERROR),
            (ValidationExecutionError, ErrorCode.VALIDATION_EXECUTION_ERROR),
            (ValidationTimeoutError, ErrorCode.VALIDATION_TIMEOUT),
            (ValidationCancelledError, ErrorCode.VALIDATION_CANCELLED),
            (SchemaValidationError, ErrorCode.SCHEMA_ERROR),
            (LanguageValidationError, ErrorCode.LANGUAGE_ERROR),
            (EncodingValidationError, ErrorCode.ENCODING_ERROR),
            (FileValidationError, ErrorCode.FILE_ERROR),
            (ContextValidationError, ErrorCode.CONTEXT_ERROR),
            (CompletenessValidationError, ErrorCode.COMPLETENESS_ERROR),
        ],
    )
    def test_validation_exception_error_code_and_recoverability(
        self, exc_class: Type[ValidationError], expected_error_code: ErrorCode
    ) -> None:
        # Arrange & Act
        err = exc_class("Validation failed")

        # Assert
        assert err.error_code == expected_error_code
        assert err.recoverable is True

    @pytest.mark.parametrize(
        "exc_class",
        [
            ValidationExecutionError,
            ValidationTimeoutError,
            ValidationCancelledError,
            SchemaValidationError,
            LanguageValidationError,
            EncodingValidationError,
            FileValidationError,
            ContextValidationError,
            CompletenessValidationError,
        ],
    )
    def test_validation_exception_inheritance_hierarchy(
        self, exc_class: Type[ValidationError]
    ) -> None:
        # Arrange & Act
        err = exc_class("Hierarchy test")

        # Assert
        assert isinstance(err, ValidationError)
        assert isinstance(err, InputValidatorError)
        assert issubclass(exc_class, ValidationError)
        assert issubclass(exc_class, InputValidatorError)

    def test_validation_execution_error_custom_error_code(self) -> None:
        # Arrange & Act
        err = ValidationExecutionError(
            "Custom execution failure", error_code=ErrorCode.UNKNOWN_ERROR
        )

        # Assert
        assert err.error_code == ErrorCode.UNKNOWN_ERROR

    def test_validation_error_custom_recoverable_flag(self) -> None:
        # Arrange & Act
        err = ValidationError("Non-recoverable validation failure", recoverable=False)

        # Assert
        assert err.recoverable is False


# ===========================================================================
# 5. Serialization Tests (to_dict)
# ===========================================================================


class TestSerialization:
    """Test suite for to_dict serialization method and immutability across exception hierarchy."""

    def test_to_dict_without_cause(self) -> None:
        # Arrange
        err = ConfigurationError(
            message="Invalid configuration parameter",
            details={"param": "timeout_ms", "value": -1},
        )

        # Act
        serialized = err.to_dict()

        # Assert
        assert serialized == {
            "message": "Invalid configuration parameter",
            "error_code": "CONFIGURATION_ERROR",
            "details": {"param": "timeout_ms", "value": -1},
            "recoverable": False,
            "timestamp": err.timestamp.isoformat(),
            "cause": None,
        }

    def test_to_dict_with_cause(self) -> None:
        # Arrange
        cause = KeyError("missing_field")
        err = SchemaValidationError(
            message="Schema validation error",
            details={"field": "query"},
            cause=cause,
        )

        # Act
        serialized = err.to_dict()

        # Assert
        assert serialized == {
            "message": "Schema validation error",
            "error_code": "SCHEMA_ERROR",
            "details": {"field": "query"},
            "recoverable": True,
            "timestamp": err.timestamp.isoformat(),
            "cause": "'missing_field'",
        }

    def test_to_dict_empty_details(self) -> None:
        # Arrange
        err = LanguageValidationError("Language not supported")

        # Act
        serialized = err.to_dict()

        # Assert
        assert serialized["details"] == {}
        assert serialized["cause"] is None

    def test_serialization_immutability(self) -> None:
        # Arrange
        initial_details = {"param": "timeout_ms", "value": 500}
        err = ConfigurationError(
            message="Original message",
            details=initial_details,
        )

        # Act
        serialized = err.to_dict()
        serialized["message"] = "MUTATED_MESSAGE"
        serialized["error_code"] = "MUTATED_CODE"
        serialized["recoverable"] = True
        serialized["timestamp"] = "2000-01-01T00:00:00+00:00"
        serialized["cause"] = "MUTATED_CAUSE"
        serialized["details"] = {"param": "mutated"}
        serialized["extra_key"] = "extra_value"

        # Assert
        assert err.message == "Original message"
        assert err.error_code == ErrorCode.CONFIGURATION_ERROR
        assert err.details == {"param": "timeout_ms", "value": 500}
        assert err.recoverable is False
        assert "extra_key" not in err.to_dict()


# ===========================================================================
# 6. String Methods Tests (__str__ and __repr__)
# ===========================================================================


class TestStringMethods:
    """Test suite for __str__ and __repr__ formatting methods."""

    def test_str_basic_message_and_code(self) -> None:
        # Arrange
        err = InputValidatorError("Simple error", error_code=ErrorCode.UNKNOWN_ERROR)

        # Act & Assert
        assert str(err) == "[UNKNOWN_ERROR] Simple error"

    def test_str_with_details(self) -> None:
        # Arrange
        err = EncodingValidationError("Invalid UTF-8", details={"encoding": "ascii"})

        # Act & Assert
        assert str(err) == "[ENCODING_ERROR] Invalid UTF-8 (Details: {'encoding': 'ascii'})"

    def test_str_with_cause(self) -> None:
        # Arrange
        cause = ValueError("Bad bytes")
        err = FileValidationError("File corrupt", cause=cause)

        # Act & Assert
        assert (
            str(err)
            == "[FILE_ERROR] File corrupt | Cause: ValueError(Bad bytes)"
        )

    def test_str_with_details_and_cause(self) -> None:
        # Arrange
        cause = TypeError("Expected str")
        err = ContextValidationError(
            "Context invalid", details={"context_len": 0}, cause=cause
        )

        # Act & Assert
        assert (
            str(err)
            == "[CONTEXT_ERROR] Context invalid (Details: {'context_len': 0}) | Cause: TypeError(Expected str)"
        )

    def test_repr_formatting(self) -> None:
        # Arrange
        err = ValidationTimeoutError("Pipeline timed out", details={"limit_ms": 1000})

        # Act
        representation = repr(err)

        # Assert
        assert representation.startswith("ValidationTimeoutError(")
        assert "error_code=VALIDATION_TIMEOUT" in representation
        assert "message='Pipeline timed out'" in representation
        assert "recoverable=True" in representation
        assert f"timestamp={err.timestamp.isoformat()}" in representation


# ===========================================================================
# 7. Exception Chaining Tests
# ===========================================================================


class TestExceptionChaining:
    """Test suite for Python exception chaining (__cause__) preservation."""

    def test_explicit_cause_preservation(self) -> None:
        # Arrange
        underlying = ValueError("Numeric overflow")

        # Act
        err = CompletenessValidationError("Input incomplete", cause=underlying)

        # Assert
        assert err.__cause__ is underlying
        assert isinstance(err.__cause__, ValueError)
        assert str(err.__cause__) == "Numeric overflow"

    def test_raise_from_chaining(self) -> None:
        # Arrange
        underlying = KeyError("missing_key")

        # Act & Assert
        with pytest.raises(SchemaValidationError) as exc_info:
            try:
                raise underlying
            except KeyError as e:
                raise SchemaValidationError("Invalid schema", cause=e) from e

        assert exc_info.type is SchemaValidationError
        assert exc_info.value.__cause__ is underlying


# ===========================================================================
# 8. Timestamp Handling Tests
# ===========================================================================


class TestTimestampHandling:
    """Test suite for timezone-aware UTC timestamp creation."""

    def test_timestamp_is_utc_timezone_aware(self) -> None:
        # Arrange & Act
        err = InputValidatorError("Timestamp test")

        # Assert
        assert isinstance(err.timestamp, datetime)
        assert err.timestamp.tzinfo is timezone.utc

    def test_timestamp_freshness(self) -> None:
        # Arrange
        before = datetime.now(timezone.utc)

        # Act
        err = InputValidatorError("Fresh timestamp")

        # Assert
        after = datetime.now(timezone.utc)
        assert before <= err.timestamp <= after


# ===========================================================================
# 9. Python Exception Semantics & Raising Tests
# ===========================================================================


class TestPythonExceptionBehavior:
    """Test suite for standard Python exception handling and catching."""

    @pytest.mark.parametrize(
        "exc_class",
        [
            InputValidatorError,
            ConfigurationError,
            ValidatorRegistrationError,
            ValidatorInitializationError,
            ValidationError,
            ValidationExecutionError,
            ValidationTimeoutError,
            ValidationCancelledError,
            SchemaValidationError,
            LanguageValidationError,
            EncodingValidationError,
            FileValidationError,
            ContextValidationError,
            CompletenessValidationError,
        ],
    )
    def test_raise_and_catch_exact_exception(
        self, exc_class: Type[InputValidatorError]
    ) -> None:
        # Arrange, Act & Assert
        with pytest.raises(exc_class) as exc_info:
            raise exc_class("Exception raise test")

        assert exc_info.type is exc_class
        assert exc_info.value.message == "Exception raise test"

    @pytest.mark.parametrize(
        "exc_class",
        [
            ValidationExecutionError,
            ValidationTimeoutError,
            ValidationCancelledError,
            SchemaValidationError,
            LanguageValidationError,
            EncodingValidationError,
            FileValidationError,
            ContextValidationError,
            CompletenessValidationError,
        ],
    )
    def test_catch_validation_exceptions_by_base_validation_error(
        self, exc_class: Type[ValidationError]
    ) -> None:
        # Arrange, Act & Assert
        with pytest.raises(ValidationError) as exc_info:
            raise exc_class("Catch by ValidationError base")

        assert exc_info.type is exc_class

    @pytest.mark.parametrize(
        "exc_class",
        [
            ConfigurationError,
            ValidatorRegistrationError,
            ValidatorInitializationError,
            ValidationError,
            ValidationExecutionError,
            ValidationTimeoutError,
            ValidationCancelledError,
            SchemaValidationError,
            LanguageValidationError,
            EncodingValidationError,
            FileValidationError,
            ContextValidationError,
            CompletenessValidationError,
        ],
    )
    def test_catch_all_exceptions_by_base_input_validator_error(
        self, exc_class: Type[InputValidatorError]
    ) -> None:
        # Arrange, Act & Assert
        with pytest.raises(InputValidatorError) as exc_info:
            raise exc_class("Catch by InputValidatorError base")

        assert exc_info.type is exc_class
