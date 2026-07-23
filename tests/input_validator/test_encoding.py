# test_encoding.py
"""Unit tests for EncodingValidator in input_validator.validators."""

import pytest
from input_validator.validators.encoding import EncodingValidator
from input_validator.models import ValidationResult


class TestEncodingValidator:
    """Test suite for EncodingValidator checking unicode surrogate pairs and byte fields."""

    def test_properties(self) -> None:
        validator = EncodingValidator(config=None)
        assert validator.validator_name == "EncodingValidator"
        assert validator.priority == 15

    def test_valid_utf8_prompt_and_context(self) -> None:
        validator = EncodingValidator(config=None)
        prompt = "Normal UTF-8 string with emoji 🔒 and unicode 漢字."
        context = {"raw_bytes": "valid text".encode("utf-8")}

        result = validator.validate(prompt, context)
        assert isinstance(result, ValidationResult)
        assert result.is_valid is True
        assert result.metadata["has_surrogates"] is False
        assert result.metadata["checked_context_byte_keys"] == 1

    def test_prompt_with_unpaired_surrogates(self) -> None:
        validator = EncodingValidator(config=None)
        # High surrogate character without low surrogate
        surrogate_prompt = "Corrupt unicode \uD800 char"
        result = validator.validate(surrogate_prompt, {})
        assert result.is_valid is False
        assert result.error_message is not None
        assert "invalid unicode surrogate characters" in result.error_message
        assert result.metadata["reason"] == "isolated_surrogates"

    def test_invalid_utf8_byte_in_context(self) -> None:
        validator = EncodingValidator(config=None)
        prompt = "Valid prompt"
        context = {"file_content": b"\x80\x81 invalid byte sequence"}
        result = validator.validate(prompt, context)
        assert result.is_valid is False
        assert result.error_message is not None
        assert "invalid UTF-8 byte encoding" in result.error_message
        assert "file_content" in result.metadata["invalid_byte_keys"]
