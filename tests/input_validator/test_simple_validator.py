# test_simple_validator.py
"""Unit tests for SimpleValidator in input_validator.validators."""

import pytest
from input_validator.validators.simple_validator import SimpleValidator
from input_validator.models import ValidationResult


class TestSimpleValidator:
    """Test suite for SimpleValidator base helper class."""

    def test_default_behavior(self) -> None:
        validator = SimpleValidator()
        assert validator.validator_name == "SimpleValidator"
        result = validator.validate("Any prompt", {"key": "val"})
        assert isinstance(result, ValidationResult)
        assert result.is_valid is True
        assert result.error_message is None

    def test_extract_context_data(self) -> None:
        validator = SimpleValidator()
        data = {"user_id": 42, "role": "admin"}
        assert validator.extract_context_data(data) == data
        assert validator.extract_context_data(None) == {}  # type: ignore
        assert validator.extract_context_data("not a dict") == {}  # type: ignore

    def test_get_context_key(self) -> None:
        validator = SimpleValidator()
        context = {"api_key": "sec_12345"}
        assert validator.get_context_key(context, "api_key") == "sec_12345"
        assert validator.get_context_key(context, "missing_key", default="fallback") == "fallback"
        assert validator.get_context_key(None, "api_key", default="fallback") == "fallback"  # type: ignore
