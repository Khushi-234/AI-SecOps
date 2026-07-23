"""
Enterprise-grade unit test suite for LengthValidator component.

Validates constructor configuration injection, boundary conditions (min-1, min, min+1, max-1, max, max+1),
success prompt checks, failure prompt checks, metadata telemetries, custom configurations,
stateless repeated execution, multi-instance independence, and context immutability.
"""

import copy
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from input_validator.config import LengthConfig
from input_validator.models import ValidationResult
from input_validator.validators.length import LengthValidator

# ===========================================================================
# 1. TestConstructor
# ===========================================================================


class TestConstructor:
    """Test suite for LengthValidator construction and public properties."""

    def test_constructor_initialization(self) -> None:
        # Arrange
        config = LengthConfig(minimum_length=5, maximum_length=100, maximum_tokens=50)

        # Act
        validator = LengthValidator(config=config)

        # Assert
        assert validator.config is config
        assert validator.config.minimum_length == 5
        assert validator.config.maximum_length == 100
        assert validator.config.maximum_tokens == 50

    def test_validator_name_property(self) -> None:
        # Arrange & Act
        validator = LengthValidator(config=LengthConfig())

        # Assert
        assert validator.validator_name == "LengthValidator"

    def test_priority_property(self) -> None:
        # Arrange & Act
        validator = LengthValidator(config=LengthConfig())

        # Assert
        assert validator.priority == 20


# ===========================================================================
# 2. TestValidationSuccess
# ===========================================================================


class TestValidationSuccess:
    """Test suite for valid prompt length scenarios within configured limits."""

    @pytest.mark.parametrize(
        "valid_prompt, min_len, max_len, description",
        [
            ("12345", 5, 10, "prompt length equal to minimum_length"),
            ("1234567890", 5, 10, "prompt length equal to maximum_length"),
            ("Hello world", 1, 50, "prompt length between limits"),
            ("a", 1, 10, "single character allowed"),
            ("Line 1\nLine 2\nLine 3", 5, 100, "multiline prompt"),
            ("Hello 🌟 Safe Prompt 🚀", 5, 100, "unicode prompt with emojis"),
            ("😀😃😄😁", 1, 20, "emoji prompt"),
            ("x" * 10_000, 0, 50_000, "large valid prompt"),
            ('{"query": "select * from table"}', 5, 200, "JSON string"),
            ("# Heading\n\nParagraph text", 5, 200, "Markdown text"),
            ("```python\ndef foo(): pass\n```", 5, 200, "Code block"),
            ("1234567890", 1, 20, "numbers only"),
            ("!@#$%^&*()_+-=[]{}", 1, 50, "symbols only"),
            ("漢字, Russian (Русский)", 1, 50, "mixed unicode script"),
            ("   Valid prompt with whitespace   ", 1, 100, "whitespace within limits"),
        ],
    )
    def test_validation_succeeds_for_valid_prompt_lengths(
        self, valid_prompt: str, min_len: int, max_len: int, description: str
    ) -> None:
        # Arrange
        config = LengthConfig(minimum_length=min_len, maximum_length=max_len)
        validator = LengthValidator(config=config)

        # Act
        result = validator.validate(valid_prompt)

        # Assert
        assert isinstance(result, ValidationResult)
        assert result.is_valid is True
        assert result.error_message is None
        assert result.validator_name == "LengthValidator"


# ===========================================================================
# 3. TestValidationFailure
# ===========================================================================


class TestValidationFailure:
    """Test suite for prompt length validation failures (too short or too long)."""

    def test_prompt_shorter_than_minimum_length_fails(self) -> None:
        # Arrange
        config = LengthConfig(minimum_length=10, maximum_length=100)
        validator = LengthValidator(config=config)
        short_prompt = "12345"  # len 5 < 10

        # Act
        result = validator.validate(short_prompt)

        # Assert
        assert isinstance(result, ValidationResult)
        assert result.is_valid is False
        assert (
            result.error_message
            == "Input validation failed: prompt length (5 characters) is below the configured minimum of 10."
        )
        assert result.metadata["within_limits"] is False
        assert result.metadata["character_count"] == 5

    def test_prompt_longer_than_maximum_length_fails(self) -> None:
        # Arrange
        config = LengthConfig(minimum_length=1, maximum_length=10)
        validator = LengthValidator(config=config)
        long_prompt = "12345678901"  # len 11 > 10

        # Act
        result = validator.validate(long_prompt)

        # Assert
        assert isinstance(result, ValidationResult)
        assert result.is_valid is False
        assert (
            result.error_message
            == "Input validation failed: prompt length (11 characters) exceeds the configured maximum of 10."
        )
        assert result.metadata["within_limits"] is False
        assert result.metadata["character_count"] == 11


# ===========================================================================
# 4. TestBoundaryConditions
# ===========================================================================


class TestBoundaryConditions:
    """Test suite for mandatory exact boundary checks around minimum and maximum length limits."""

    @pytest.mark.parametrize(
        "char_count, expected_valid, description",
        [
            (9, False, "minimum_length - 1 (fails)"),
            (10, True, "minimum_length (succeeds)"),
            (11, True, "minimum_length + 1 (succeeds)"),
            (19, True, "maximum_length - 1 (succeeds)"),
            (20, True, "maximum_length (succeeds)"),
            (21, False, "maximum_length + 1 (fails)"),
        ],
    )
    def test_exact_boundary_conditions(
        self, char_count: int, expected_valid: bool, description: str
    ) -> None:
        # Arrange
        min_len = 10
        max_len = 20
        config = LengthConfig(minimum_length=min_len, maximum_length=max_len)
        validator = LengthValidator(config=config)
        prompt = "a" * char_count

        # Act
        result = validator.validate(prompt)

        # Assert
        assert result.is_valid is expected_valid
        assert result.metadata["character_count"] == char_count
        assert result.metadata["minimum_length"] == min_len
        assert result.metadata["maximum_length"] == max_len
        assert result.metadata["within_limits"] is expected_valid

        if not expected_valid:
            assert result.error_message is not None
            if char_count < min_len:
                assert (
                    f"below the configured minimum of {min_len}" in result.error_message
                )
            elif char_count > max_len:
                assert (
                    f"exceeds the configured maximum of {max_len}"
                    in result.error_message
                )
        else:
            assert result.error_message is None


# ===========================================================================
# 5. TestMetadata
# ===========================================================================


class TestMetadata:
    """Test suite verifying metadata dictionary contents, structure, non-aliasing, and token placeholders."""

    def test_metadata_fields_on_success(self) -> None:
        # Arrange
        config = LengthConfig(minimum_length=2, maximum_length=20, maximum_tokens=100)
        validator = LengthValidator(config=config)
        context = {"request_id": "req-meta-pass"}

        # Act
        result = validator.validate("Hello world", context=context)

        # Assert
        assert result.metadata is not None
        assert isinstance(result.metadata, dict)
        assert result.metadata is not context
        assert result.metadata == {
            "character_count": 11,
            "minimum_length": 2,
            "maximum_length": 20,
            "maximum_tokens": 100,
            "within_limits": True,
            "request_id": "req-meta-pass",
        }

    def test_metadata_fields_on_failure(self) -> None:
        # Arrange
        config = LengthConfig(minimum_length=10, maximum_length=20, maximum_tokens=250)
        validator = LengthValidator(config=config)
        context = {"request_id": "req-meta-fail"}

        # Act
        result = validator.validate("Too short", context=context)  # len 9

        # Assert
        assert result.metadata is not None
        assert isinstance(result.metadata, dict)
        assert result.metadata is not context
        assert result.metadata == {
            "character_count": 9,
            "minimum_length": 10,
            "maximum_length": 20,
            "maximum_tokens": 250,
            "within_limits": False,
            "request_id": "req-meta-fail",
        }

    def test_maximum_tokens_appears_in_metadata(self) -> None:
        # Arrange
        config = LengthConfig(maximum_tokens=4096)
        validator = LengthValidator(config=config)

        # Act
        result = validator.validate("Test tokens metadata")

        # Assert
        assert result.metadata is not None
        assert "maximum_tokens" in result.metadata
        assert result.metadata["maximum_tokens"] == 4096


# ===========================================================================
# 6. TestConfiguration
# ===========================================================================


class TestConfiguration:
    """Test suite verifying validator adherence to injected custom configuration limits."""

    @pytest.mark.parametrize(
        "min_len, max_len, max_tokens, prompt, expected_valid",
        [
            (5, 20, 50, "1234", False),
            (5, 20, 50, "12345", True),
            (5, 20, 50, "12345678901234567890", True),
            (5, 20, 50, "123456789012345678901", False),
            (100, 200, 1000, "a" * 99, False),
            (100, 200, 1000, "a" * 150, True),
            (100, 200, 1000, "a" * 201, False),
            (0, 5, 10, "", True),
            (0, 5, 10, "12345", True),
            (0, 5, 10, "123456", False),
        ],
    )
    def test_custom_configurations(
        self,
        min_len: int,
        max_len: int,
        max_tokens: int,
        prompt: str,
        expected_valid: bool,
    ) -> None:
        # Arrange
        config = LengthConfig(
            minimum_length=min_len, maximum_length=max_len, maximum_tokens=max_tokens
        )
        validator = LengthValidator(config=config)

        # Act
        result = validator.validate(prompt)

        # Assert
        assert result.is_valid is expected_valid
        assert result.metadata["minimum_length"] == min_len
        assert result.metadata["maximum_length"] == max_len
        assert result.metadata["maximum_tokens"] == max_tokens


# ===========================================================================
# 7. TestStatelessness
# ===========================================================================


class TestStatelessness:
    """Test suite verifying stateless, deterministic repeated execution and instance independence."""

    def test_stateless_repeated_execution(self) -> None:
        # Arrange
        config = LengthConfig(minimum_length=5, maximum_length=15)
        validator = LengthValidator(config=config)
        iterations = 50

        # Act & Assert
        for i in range(iterations):
            valid_result = validator.validate("Valid length")
            assert valid_result.is_valid is True
            assert valid_result.metadata["character_count"] == 12

            invalid_result = validator.validate("Tiny")
            assert invalid_result.is_valid is False
            assert invalid_result.metadata["character_count"] == 4

    def test_multiple_instances_state_independence(self) -> None:
        # Arrange
        config_1 = LengthConfig(minimum_length=2, maximum_length=10)
        config_2 = LengthConfig(minimum_length=20, maximum_length=50)

        validator_1 = LengthValidator(config=config_1)
        validator_2 = LengthValidator(config=config_2)

        prompt = "12345"  # len 5

        # Act
        result_1 = validator_1.validate(prompt)
        result_2 = validator_2.validate(prompt)

        # Assert
        assert result_1.is_valid is True
        assert result_2.is_valid is False
        assert result_1.metadata["maximum_length"] == 10
        assert result_2.metadata["maximum_length"] == 50


# ===========================================================================
# 8. TestImmutability
# ===========================================================================


class TestImmutability:
    """Test suite verifying input context immutability."""

    def test_context_dictionary_is_not_modified(self) -> None:
        # Arrange
        config = LengthConfig()
        validator = LengthValidator(config=config)
        original_context = {
            "request_id": "req-length-immutable",
            "client_ip": "127.0.0.1",
            "nested_config": {"trace": True},
        }
        context_snapshot = copy.deepcopy(original_context)

        # Act
        validator.validate("Valid prompt", context=original_context)

        # Assert
        assert original_context == context_snapshot
        assert original_context["nested_config"]["trace"] is True


# ===========================================================================
# 9. TestValidationResultContract
# ===========================================================================


class TestValidationResultContract:
    """Test suite verifying validation result object fields, timing, and UTC timestamping."""

    def test_validation_result_fields(self) -> None:
        # Arrange
        config = LengthConfig(minimum_length=1, maximum_length=50)
        validator = LengthValidator(config=config)
        context = {"request_id": "req-contract"}

        # Act
        result = validator.validate("Valid text", context=context)

        # Assert
        assert result.validator_name == "LengthValidator"
        assert result.is_valid is True
        assert result.error_message is None
        assert isinstance(result.execution_time_ms, float)
        assert result.execution_time_ms >= 0.0
        assert isinstance(result.timestamp, datetime)
        assert result.timestamp.tzinfo is not None
        assert result.timestamp.utcoffset() == timedelta(0)
        assert result.metadata is not None
        assert result.metadata is not context
        assert result.metadata["character_count"] == 10

    @pytest.mark.parametrize("non_string_input", [None, 123, 4.56, [], {}])
    def test_non_string_prompt_handled_by_base_validator(
        self, non_string_input: Any
    ) -> None:
        # Arrange
        validator = LengthValidator(config=LengthConfig())

        # Act
        result = validator.validate(non_string_input)

        # Assert
        assert result.is_valid is False
        assert "Input prompt must be a string" in (result.error_message or "")
        assert result.metadata.get("validator_name") == "LengthValidator"
