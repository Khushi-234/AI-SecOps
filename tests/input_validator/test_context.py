# test_context.py
"""Unit tests for ValidationContext component in input_validator."""

import pytest
from input_validator.context import ValidationContext
from input_validator.models import (
    ConversationPayload,
    ConversationMessage,
    ValidationResult,
)


class TestValidationContext:
    """Test suite for ValidationContext checking history length, roles, and character limits."""

    def test_default_initialization(self) -> None:
        context_validator = ValidationContext()
        assert context_validator.max_history_turns == 50
        assert context_validator.max_total_chars == 20000
        assert context_validator.allowed_roles == {"system", "user", "assistant"}

    def test_custom_initialization(self) -> None:
        context_validator = ValidationContext(
            max_history_turns=10, max_total_chars=1000, allowed_roles=["user", "admin"]
        )
        assert context_validator.max_history_turns == 10
        assert context_validator.max_total_chars == 1000
        assert context_validator.allowed_roles == {"user", "admin"}

    def test_successful_validation(self) -> None:
        context_validator = ValidationContext(max_history_turns=5, max_total_chars=500)
        payload = ConversationPayload(
            user="What is the weather today?",
            history=[
                ConversationMessage(
                    role="system", content="You are a helpful assistant."
                ),
                ConversationMessage(role="user", content="Hello!"),
                ConversationMessage(
                    role="assistant", content="Hi there! How can I help?"
                ),
            ],
        )
        result = context_validator.validate(payload)
        assert isinstance(result, ValidationResult)
        assert result.is_valid is True
        assert result.validator_name == "ValidationContext"
        assert result.error_message is None
        assert result.metadata["turn_count"] == 3
        assert result.metadata["total_chars"] > 0

    def test_empty_user_prompt(self) -> None:
        context_validator = ValidationContext()
        payload = ConversationPayload(user="", history=[])
        result = context_validator.validate(payload)
        assert result.is_valid is False
        assert result.error_message is not None
        assert "cannot be empty" in result.error_message.lower()
        assert result.metadata["reason"] == "empty_user_prompt"

    def test_whitespace_only_user_prompt(self) -> None:
        context_validator = ValidationContext()
        payload = ConversationPayload(user="   \n\t  ", history=[])
        result = context_validator.validate(payload)
        assert result.is_valid is False
        assert result.error_message is not None
        assert "cannot be empty" in result.error_message.lower()
        assert result.metadata["reason"] == "empty_user_prompt"

    def test_exceeds_max_history_turns(self) -> None:
        context_validator = ValidationContext(max_history_turns=2)
        history = [
            ConversationMessage(role="user", content=f"Turn {i}") for i in range(3)
        ]
        payload = ConversationPayload(user="Latest query", history=history)
        result = context_validator.validate(payload)
        assert result.is_valid is False
        assert result.error_message is not None
        assert "exceeds limit of 2 turns" in result.error_message
        assert result.metadata["turn_count"] == 3
        assert result.metadata["max_turns"] == 2

    def test_invalid_speaker_role(self) -> None:
        context_validator = ValidationContext(allowed_roles=["user", "assistant"])
        payload = ConversationPayload(
            user="Hello",
            history=[
                ConversationMessage(role="system", content="System prompt"),
            ],
        )
        result = context_validator.validate(payload)
        assert result.is_valid is False
        assert result.error_message is not None
        assert "Invalid role 'system'" in result.error_message
        assert result.metadata["index"] == 0
        assert result.metadata["invalid_role"] == "system"

    def test_exceeds_max_total_chars(self) -> None:
        context_validator = ValidationContext(max_total_chars=50)
        payload = ConversationPayload(
            user="A" * 30, history=[ConversationMessage(role="user", content="B" * 30)]
        )
        result = context_validator.validate(payload)
        assert result.is_valid is False
        assert result.error_message is not None
        assert "exceeds maximum allowance of 50 characters" in result.error_message
        assert result.metadata["total_chars"] == 60
        assert result.metadata["max_chars"] == 50
