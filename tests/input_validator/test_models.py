# test_models.py
"""Unit tests for dataclass models in input_validator."""

import pytest
from datetime import datetime, timezone
from dataclasses import FrozenInstanceError
from input_validator.models import (
    ValidationResult,
    ConversationMessage,
    ConversationPayload,
    InputValidationResponse,
)


class TestModels:
    """Test suite verifying dataclasses behavior, frozen immutability, and defaults."""

    def test_validation_result_defaults_and_fields(self) -> None:
        res = ValidationResult(validator_name="TestVal", is_valid=True)
        assert res.validator_name == "TestVal"
        assert res.is_valid is True
        assert res.error_message is None
        assert res.execution_time_ms == 0.0
        assert isinstance(res.timestamp, datetime)
        assert res.timestamp.tzinfo == timezone.utc
        assert res.metadata == {}

    def test_validation_result_immutability(self) -> None:
        res = ValidationResult(validator_name="TestVal", is_valid=True)
        with pytest.raises(FrozenInstanceError):
            res.is_valid = False  # type: ignore

    def test_conversation_message(self) -> None:
        msg = ConversationMessage(role="user", content="Hello world")
        assert msg.role == "user"
        assert msg.content == "Hello world"
        with pytest.raises(FrozenInstanceError):
            msg.role = "assistant"  # type: ignore

    def test_conversation_payload_defaults(self) -> None:
        payload = ConversationPayload(user="Main query")
        assert payload.user == "Main query"
        assert payload.history == []

    def test_conversation_payload_with_history(self) -> None:
        msgs = [
            ConversationMessage(role="system", content="Init"),
            ConversationMessage(role="user", content="Hi")
        ]
        payload = ConversationPayload(user="Main query", history=msgs)
        assert payload.user == "Main query"
        assert len(payload.history) == 2
        assert payload.history[0].role == "system"

    def test_input_validation_response_defaults_and_fields(self) -> None:
        v_res = ValidationResult(validator_name="TestVal", is_valid=True)
        resp = InputValidationResponse(is_valid=True, results=[v_res], execution_time_ms=1.5)
        assert resp.is_valid is True
        assert len(resp.results) == 1
        assert resp.execution_time_ms == 1.5
        assert resp.metadata == {}
        with pytest.raises(FrozenInstanceError):
            resp.is_valid = False  # type: ignore
