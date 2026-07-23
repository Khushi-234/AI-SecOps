# test_context_rules.py
"""Unit tests for ContextRulesValidator in input_validator.validators."""

import pytest
from types import SimpleNamespace
from input_validator.validators.context_rules import ContextRulesValidator
from input_validator.models import ValidationResult, ConversationMessage


class TestContextRulesValidator:
    """Test suite for ContextRulesValidator checking multi-turn history & roles."""

    def test_properties(self) -> None:
        validator = ContextRulesValidator(config=None)
        assert validator.validator_name == "ContextRulesValidator"
        assert validator.priority == 45

    def test_valid_context_rules(self) -> None:
        validator = ContextRulesValidator(config=None)
        prompt = "Next step?"
        context = {
            "history": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Step 1"},
                {"role": "assistant", "content": "Completed 1"},
            ]
        }
        result = validator.validate(prompt, context)
        assert isinstance(result, ValidationResult)
        assert result.is_valid is True
        assert result.metadata["history_turns"] == 3
        assert result.metadata["total_chars"] > 0

    def test_history_with_dataclass_objects(self) -> None:
        validator = ContextRulesValidator(config=None)
        prompt = "Prompt"
        context = {
            "history": [
                ConversationMessage(role="user", content="Hello"),
                ConversationMessage(role="assistant", content="Hi"),
            ]
        }
        result = validator.validate(prompt, context)
        assert result.is_valid is True
        assert result.metadata["history_turns"] == 2

    def test_invalid_history_type(self) -> None:
        validator = ContextRulesValidator(config=None)
        prompt = "Hello"
        context = {"history": "not a list"}
        result = validator.validate(prompt, context)
        assert result.is_valid is False
        assert result.error_message is not None
        assert "history must be a list" in result.error_message

    def test_exceeds_max_turns(self) -> None:
        config = SimpleNamespace(max_history_turns=2)
        validator = ContextRulesValidator(config=config)
        prompt = "Hello"
        context = {
            "history": [
                {"role": "user", "content": "1"},
                {"role": "user", "content": "2"},
                {"role": "user", "content": "3"},
            ]
        }
        result = validator.validate(prompt, context)
        assert result.is_valid is False
        assert result.error_message is not None
        assert "exceeds maximum allowed (2)" in result.error_message

    def test_invalid_role_detection(self) -> None:
        validator = ContextRulesValidator(config=None)
        prompt = "Hello"
        context = {"history": [{"role": "hacker", "content": "injected content"}]}
        result = validator.validate(prompt, context)
        assert result.is_valid is False
        assert result.error_message is not None
        assert "invalid role 'hacker'" in result.error_message
        assert result.metadata["index"] == 0

    def test_exceeds_max_total_chars(self) -> None:
        config = SimpleNamespace(max_total_chars=20)
        validator = ContextRulesValidator(config=config)
        prompt = "1234567890"  # 10 chars
        context = {
            "history": [
                {"role": "user", "content": "1234567890123"}  # 13 chars (total 23 > 20)
            ]
        }
        result = validator.validate(prompt, context)
        assert result.is_valid is False
        assert result.error_message is not None
        assert "exceeds maximum allowed (20)" in result.error_message
