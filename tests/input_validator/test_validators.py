"""
Unit tests for input_validator concrete validator components.
"""

from __future__ import annotations

import pytest
from input_validator.validators.empty import EmptyValidator
from input_validator.validators.length import LengthValidator
from input_validator.validators.encoding import EncodingValidator
from input_validator.validators.format import FormatValidator
from input_validator.validators.context_rules import ContextRulesValidator
from input_validator.validators.file_validator import FileValidator
from input_validator.validators.completeness import CompletenessValidator
from input_validator.validators.simple_validator import SimpleValidator
from input_validator.config import LengthConfig, InputValidatorConfig


def test_simple_validator():
    validator = SimpleValidator()
    assert validator.extract_context_data({"a": 1}) == {"a": 1}
    assert validator.get_context_key({"req_id": "123"}, "req_id") == "123"


def test_encoding_validator():
    validator = EncodingValidator(config=None)
    # Valid prompt
    result = validator.validate("Hello world", {})
    assert result.is_valid is True

    # Surrogate character prompt
    result = validator.validate("Bad \ud800 surrogate", {})
    assert result.is_valid is False
    assert result.error_message is not None, "Expected an error message when validation fails"
    assert "surrogate" in result.error_message.lower()


def test_format_validator():
    validator = FormatValidator(config=None)
    # Valid email in context
    result = validator.validate("Sample prompt", {"email": "user@example.com"})
    assert result.is_valid is True

    # Invalid email in context
    result = validator.validate("Sample prompt", {"email": "not-an-email"})
    assert result.is_valid is False


def test_context_rules_validator():
    validator = ContextRulesValidator(config=None)
    history = [
        {"role": "user", "content": "Hello"},
        {"role": "assistant", "content": "Hi there!"},
    ]
    result = validator.validate("Can you help me?", {"history": history})
    assert result.is_valid is True

    # Invalid role in history
    bad_history = [{"role": "hacker", "content": "evil"}]
    result = validator.validate("Prompt", {"history": bad_history})
    assert result.is_valid is False


def test_file_validator():
    validator = FileValidator(config=None)
    # Path traversal attack block
    result = validator.validate("Prompt", {"file_path": "../../../etc/passwd"})
    assert result.is_valid is False
    assert result.error_message is not None, "Expected an error message when validation fails"
    
    error_msg = result.error_message.lower()
    assert "path traversal" in error_msg or "restricted" in error_msg


def test_completeness_validator():
    validator = CompletenessValidator(config=None)
    # Missing required 'user' prompt
    result = validator.validate("", {"request_id": "123"})
    assert result.is_valid is False

    # Valid complete request
    result = validator.validate("Valid prompt", {"request_id": "123"})
    assert result.is_valid is True
