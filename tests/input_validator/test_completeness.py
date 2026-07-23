# test_completeness.py
"""Unit tests for CompletenessValidator in input_validator.validators."""

import pytest
from types import SimpleNamespace
from input_validator.validators.completeness import CompletenessValidator
from input_validator.models import ValidationResult


class TestCompletenessValidator:
    """Test suite for CompletenessValidator component."""

    def test_properties(self) -> None:
        validator = CompletenessValidator(config=None)
        assert validator.validator_name == "CompletenessValidator"
        assert validator.priority == 65

    def test_valid_payload_with_default_fields(self) -> None:
        validator = CompletenessValidator(config=None)
        prompt = "Explain LLM security."
        context = {"request_id": "req-12345"}

        result = validator.validate(prompt, context)
        assert isinstance(result, ValidationResult)
        assert result.is_valid is True
        assert result.error_message is None
        assert result.metadata["is_complete"] is True
        assert result.metadata["missing_fields"] == []

    def test_missing_user_prompt(self) -> None:
        validator = CompletenessValidator(config=None)
        prompt = ""
        context = {"request_id": "req-12345"}

        result = validator.validate(prompt, context)
        assert result.is_valid is False
        assert "user" in result.metadata["missing_fields"]
        assert result.error_message is not None
        assert "missing or empty required fields: user" in result.error_message

    def test_missing_context_required_field(self) -> None:
        validator = CompletenessValidator(config=None)
        prompt = "Valid prompt"
        context = {}

        result = validator.validate(prompt, context)
        assert result.is_valid is False
        assert "request_id" in result.metadata["missing_fields"]
        assert result.error_message is not None
        assert "missing or empty required fields: request_id" in result.error_message

    def test_custom_required_fields_from_config(self) -> None:
        config = SimpleNamespace(required_fields=["user", "user_id", "session_token"])
        validator = CompletenessValidator(config=config)
        prompt = "Hello"
        context = {"user_id": "user-12"}

        result = validator.validate(prompt, context)
        assert result.is_valid is False
        assert "session_token" in result.metadata["missing_fields"]
        assert result.error_message is not None
        assert "session_token" in result.error_message

    def test_dict_style_required_fields_in_config(self) -> None:
        config = SimpleNamespace(required_fields={"user": str, "app_id": str})
        validator = CompletenessValidator(config=config)
        prompt = "Prompt"
        context = {"app_id": "app-01"}

        result = validator.validate(prompt, context)
        assert result.is_valid is True
        assert result.metadata["is_complete"] is True
