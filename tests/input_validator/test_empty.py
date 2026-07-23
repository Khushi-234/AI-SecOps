"""
Enterprise-grade unit test suite for EmptyValidator component.

Validates constructor initialization, success prompt checks, empty/whitespace failure checks,
edge cases, result contract attributes, execution timing, timezone-aware UTC timestamping,
stateless execution, metadata non-aliasing, and context immutability.
"""

import copy
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from input_validator.config import InputValidatorConfig
from input_validator.models import ValidationResult
from input_validator.validators.empty import EmptyValidator

# ===========================================================================
# 1. TestConstructor
# ===========================================================================


class TestConstructor:
    """Test suite for EmptyValidator construction and public properties."""

    def test_constructor_initialization(self) -> None:
        # Arrange
        config = InputValidatorConfig()

        # Act
        validator = EmptyValidator(config=config)

        # Assert
        assert validator.config is config
        assert isinstance(validator.config, InputValidatorConfig)

    def test_constructor_with_none_config(self) -> None:
        # Arrange & Act
        validator = EmptyValidator(config=None)

        # Assert
        assert validator.config is None

    def test_validator_name_property(self) -> None:
        # Arrange & Act
        validator = EmptyValidator(config=None)

        # Assert
        assert validator.validator_name == "EmptyValidator"

    def test_priority_property(self) -> None:
        # Arrange & Act
        validator = EmptyValidator(config=None)

        # Assert
        assert validator.priority == 10


# ===========================================================================
# 2. TestValidationSuccess
# ===========================================================================


class TestValidationSuccess:
    """Test suite for valid, non-empty prompt validation scenarios."""

    @pytest.mark.parametrize(
        "valid_prompt, description",
        [
            ("Hello world", "simple sentence"),
            ("a", "single character"),
            ("  a  ", "single character with whitespace padding"),
            ("\t\n  x  \r\n", "single character with mixed whitespace padding"),
            (
                "   Leading and trailing whitespace around valid prompt   ",
                "prompt with leading and trailing whitespace",
            ),
            ("Line 1\nLine 2\nLine 3", "multi-line prompt"),
            ("Hello 🌟 Safe Prompt 🚀", "unicode with emoji"),
            ("😀😃😄😁", "emoji prompt"),
            ("x" * 100_000, "large prompt"),
            ('{"query": "select * from users"}', "JSON string"),
            ("<request><id>123</id></request>", "XML string"),
            ("# Heading\n\n- item 1\n- item 2", "Markdown text"),
            ("```python\ndef foo(): pass\n```", "Code block"),
            ("1234567890", "numbers only"),
            ("!@#$%^&*()_+-=[]{}|;:'\",.<>/?~`", "symbols only"),
            ("漢字, Cyrillic (Русский), Arabic (العربية)", "mixed unicode scripts"),
        ],
    )
    def test_validation_succeeds_for_valid_prompts(
        self, valid_prompt: str, description: str
    ) -> None:
        # Arrange
        validator = EmptyValidator(config=InputValidatorConfig())

        # Act
        result = validator.validate(valid_prompt)

        # Assert
        assert isinstance(result, ValidationResult)
        assert result.is_valid is True
        assert result.error_message is None
        assert result.validator_name == "EmptyValidator"


# ===========================================================================
# 3. TestValidationFailures
# ===========================================================================


class TestValidationFailures:
    """Test suite for empty and whitespace-only prompt validation failures."""

    @pytest.mark.parametrize(
        "invalid_prompt, description",
        [
            ("", "empty string"),
            (" ", "single space"),
            ("   ", "multiple spaces"),
            ("\t", "single tab"),
            ("\t\t\t", "multiple tabs"),
            ("\n", "single newline"),
            ("\n\n\n", "multiple newlines"),
            ("\r", "carriage return"),
            ("\r\n", "carriage return + newline"),
            ("\t \n \r ", "mixed whitespace"),
            ("\t\n", "tab + newline"),
            (" \n", "space + newline"),
            (" " * 10_000, "very long whitespace string"),
            ("\u2000\u2001\u2002\u2003\u3000\u00a0", "unicode whitespace characters"),
        ],
    )
    def test_validation_fails_for_empty_or_whitespace_prompts(
        self, invalid_prompt: str, description: str
    ) -> None:
        # Arrange
        validator = EmptyValidator(config=InputValidatorConfig())

        # Act
        result = validator.validate(invalid_prompt)

        # Assert
        assert isinstance(result, ValidationResult)
        assert result.is_valid is False
        assert (
            result.error_message == "Input prompt is empty or contains only whitespace"
        )
        assert result.validator_name == "EmptyValidator"


# ===========================================================================
# 4. TestEdgeCases
# ===========================================================================


class TestEdgeCases:
    """Test suite for boundary edge cases and non-string input types."""

    @pytest.mark.parametrize(
        "whitespace_prompt",
        [
            "",
            " ",
            "\t",
            "\n",
            "\r",
            "\r\n",
            "\t\n",
            "\n\t",
            "     ",
            "\u2009",  # thin space
            "\u3000",  # ideographic space
            "\u00a0",  # non-breaking space
        ],
    )
    def test_edge_case_whitespace_inputs(self, whitespace_prompt: str) -> None:
        # Arrange
        validator = EmptyValidator(config=InputValidatorConfig())

        # Act
        result = validator.validate(whitespace_prompt)

        # Assert
        assert result.is_valid is False
        assert (
            result.error_message == "Input prompt is empty or contains only whitespace"
        )

    @pytest.mark.parametrize(
        "non_string_input",
        [
            None,
            123,
            45.67,
            [],
            {},
            True,
        ],
    )
    def test_non_string_input_prompt_returns_failed_result(
        self, non_string_input: Any
    ) -> None:
        # Arrange
        validator = EmptyValidator(config=InputValidatorConfig())

        # Act
        result = validator.validate(non_string_input)

        # Assert
        assert result.is_valid is False
        assert "Input prompt must be a string" in (result.error_message or "")
        assert result.metadata.get("validator_name") == "EmptyValidator"


# ===========================================================================
# 5. TestValidationResult
# ===========================================================================


class TestValidationResult:
    """Test suite verifying contract properties on returned ValidationResult objects."""

    def test_validation_result_contract_success(self) -> None:
        # Arrange
        validator = EmptyValidator(config=InputValidatorConfig())
        context = {"request_id": "req-pass-1"}

        # Act
        result = validator.validate("Valid text", context=context)

        # Assert
        assert result.validator_name == "EmptyValidator"
        assert result.is_valid is True
        assert result.error_message is None
        assert isinstance(result.execution_time_ms, float)
        assert result.execution_time_ms >= 0.0
        assert isinstance(result.timestamp, datetime)
        assert result.timestamp.tzinfo is not None
        assert result.timestamp.utcoffset() == timedelta(0)
        assert result.metadata is not None
        assert isinstance(result.metadata, dict)
        assert result.metadata is not context
        assert result.metadata["request_id"] == "req-pass-1"

    def test_validation_result_contract_failure(self) -> None:
        # Arrange
        validator = EmptyValidator(config=InputValidatorConfig())
        context = {"request_id": "req-fail-1"}

        # Act
        result = validator.validate("   ", context=context)

        # Assert
        assert result.validator_name == "EmptyValidator"
        assert result.is_valid is False
        assert (
            result.error_message == "Input prompt is empty or contains only whitespace"
        )
        assert isinstance(result.execution_time_ms, float)
        assert result.execution_time_ms >= 0.0
        assert isinstance(result.timestamp, datetime)
        assert result.timestamp.tzinfo is not None
        assert result.timestamp.utcoffset() == timedelta(0)
        assert result.metadata is not None
        assert isinstance(result.metadata, dict)
        assert result.metadata is not context
        assert result.metadata["request_id"] == "req-fail-1"


# ===========================================================================
# 6. TestStatelessExecution
# ===========================================================================


class TestStatelessExecution:
    """Test suite verifying stateless, deterministic repeated execution."""

    def test_stateless_repeated_execution(self) -> None:
        # Arrange
        validator = EmptyValidator(config=InputValidatorConfig())
        iterations = 100

        # Act & Assert
        for i in range(iterations):
            valid_result = validator.validate(f"Prompt iteration {i}")
            assert valid_result.is_valid is True

            invalid_result = validator.validate("   ")
            assert invalid_result.is_valid is False


# ===========================================================================
# 7. TestImmutability
# ===========================================================================


class TestImmutability:
    """Test suite verifying input context immutability."""

    def test_context_dictionary_is_not_modified(self) -> None:
        # Arrange
        validator = EmptyValidator(config=InputValidatorConfig())
        original_context = {
            "request_id": "req-immutable-1",
            "user_role": "admin",
            "metadata_nest": {"nested_key": "nested_val"},
        }
        context_snapshot = copy.deepcopy(original_context)

        # Act
        validator.validate("Valid prompt", context=original_context)

        # Assert
        assert original_context == context_snapshot
        assert original_context["metadata_nest"]["nested_key"] == "nested_val"
