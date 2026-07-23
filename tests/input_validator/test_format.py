# test_format.py
"""Unit tests for FormatValidator in input_validator.validators."""

import pytest
from types import SimpleNamespace
from input_validator.validators.format import FormatValidator
from input_validator.models import ValidationResult


class TestFormatValidator:
    """Test suite for FormatValidator checking regex patterns and JSON prompt structure."""

    def test_properties(self) -> None:
        validator = FormatValidator(config=None)
        assert validator.validator_name == "FormatValidator"
        assert validator.priority == 35

    def test_valid_email_uuid_and_url(self) -> None:
        validator = FormatValidator(config=None)
        prompt = "Regular user request"
        context = {
            "email": "user@example.com",
            "uuid": "123e4567-e89b-12d3-a456-426614174000",
            "url": "https://example.com/api/v1"
        }
        result = validator.validate(prompt, context)
        assert isinstance(result, ValidationResult)
        assert result.is_valid is True
        assert result.metadata["mismatch_count"] == 0

    def test_invalid_email_format(self) -> None:
        validator = FormatValidator(config=None)
        prompt = "Hello"
        context = {"email": "invalid_email_at_domain"}
        result = validator.validate(prompt, context)
        assert result.is_valid is False
        assert result.error_message is not None
        assert "format mismatches found in fields: email" in result.error_message
        assert "email" in result.metadata["mismatched_fields"]

    def test_invalid_uuid_format(self) -> None:
        validator = FormatValidator(config=None)
        prompt = "Hello"
        context = {"uuid": "not-a-valid-uuid"}
        result = validator.validate(prompt, context)
        assert result.is_valid is False
        assert "uuid" in result.metadata["mismatched_fields"]

    def test_expected_json_format_prompt_success(self) -> None:
        validator = FormatValidator(config=None)
        prompt = '{"action": "query", "id": 123}'
        context = {"expected_format": "json"}
        result = validator.validate(prompt, context)
        assert result.is_valid is True

    def test_expected_json_format_prompt_failure(self) -> None:
        validator = FormatValidator(config=None)
        prompt = 'Not a JSON object'
        context = {"expected_format": "json"}
        result = validator.validate(prompt, context)
        assert result.is_valid is False
        assert "prompt_json" in result.metadata["mismatched_fields"]

    def test_custom_format_rules_in_config(self) -> None:
        config = SimpleNamespace(format_rules={"zipcode": r"^\d{5}$"})
        validator = FormatValidator(config=config)
        prompt = "Check zip"
        context = {"zipcode": "90210"}
        result = validator.validate(prompt, context)
        assert result.is_valid is True

        bad_context = {"zipcode": "ABCDE"}
        bad_result = validator.validate(prompt, bad_context)
        assert bad_result.is_valid is False
        assert "zipcode" in bad_result.metadata["mismatched_fields"]
