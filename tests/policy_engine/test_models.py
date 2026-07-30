"""
Unit tests for Policy Engine domain models and serialization routines.
"""

from __future__ import annotations

import pytest
from policy_engine.actions import PolicyAction
from policy_engine.context import RiskContext
from policy_engine.enums import SanitizationType
from policy_engine.exceptions import InvalidPolicyInputError
from policy_engine.models import (
    PolicyDecision,
    SanitizationEdit,
    SanitizationResult,
)


def test_sanitization_edit_creation_and_serialization():
    edit = SanitizationEdit(
        edit_id="edit_1",
        sanitization_type=SanitizationType.PII_REDACTION,
        original_text="user@example.com",
        replacement_text="[REDACTED_PII]",
        start_char=10,
        end_char=26,
    )
    assert edit.edit_id == "edit_1"
    assert edit.start_char == 10
    assert edit.end_char == 26

    dict_data = edit.to_dict()
    assert dict_data["sanitization_type"] == "PII_REDACTION"
    assert dict_data["original_text"] == "user@example.com"


def test_sanitization_edit_invalid_bounds():
    with pytest.raises(InvalidPolicyInputError):
        SanitizationEdit(
            edit_id="invalid",
            sanitization_type=SanitizationType.PII_REDACTION,
            original_text="test",
            replacement_text="[REDACTED]",
            start_char=20,
            end_char=10,  # start > end
        )


def test_risk_context_validation():
    ctx = RiskContext(
        request_id="req_100",
        original_prompt="Hello world",
        risk_score=15.0,
        confidence_score=0.90,
        risk_level="LOW",
    )
    assert ctx.request_id == "req_100"
    assert ctx.risk_score == 15.0
    assert ctx.score_100 == 15.0
    assert ctx.composite_score == 0.15

    with pytest.raises(InvalidPolicyInputError):
        RiskContext(
            request_id="req_err",
            original_prompt="Hello",
            risk_score=-5.0,  # Invalid negative risk score
        )


def test_policy_decision_fields_and_serialization():
    decision = PolicyDecision(
        action=PolicyAction.ALLOW,
        reason="Low risk approved",
        risk_score=20.0,
        rule_triggered="RISK_SCORE_RULE",
        request_id="req_1",
        is_approved=True,
        final_prompt="Hello world",
    )
    assert decision.action == PolicyAction.ALLOW
    assert decision.is_approved is True
    assert decision.final_prompt == "Hello world"
    assert decision.risk_score == 20.0
    assert decision.rule_triggered == "RISK_SCORE_RULE"

    d_dict = decision.to_dict()
    assert d_dict["action"] == "ALLOW"
    assert d_dict["rule_triggered"] == "RISK_SCORE_RULE"
    assert d_dict["risk_score"] == 20.0


def test_policy_decision_block_auto_approval_override():
    # BLOCK action forces is_approved=False and final_prompt=None
    decision = PolicyDecision(
        action=PolicyAction.BLOCK,
        reason="Critical threat",
        risk_score=95.0,
        rule_triggered="THREAT_RULE",
        is_approved=True,  # gets overridden to False
        final_prompt="Prompt should be cleared",
    )
    assert decision.action == PolicyAction.BLOCK
    assert decision.is_approved is False
    assert decision.final_prompt is None


def test_risk_context_from_dict_with_none():
    payload = {
        "risk_score": None,
        "composite_score": 0.5,
        "confidence_score": None,
        "detected_threats": None,
        "risk_level": None,
        "recommended_action": None,
        "metadata": None,
    }
    ctx = RiskContext.from_risk_response(
        request_id="req_dict_none",
        original_prompt="test prompt",
        risk_response=payload,
    )
    assert ctx.risk_score == 0.5
    assert ctx.confidence_score == 1.0
    assert ctx.detected_threats == ()
    assert ctx.risk_level == "LOW"
    assert ctx.recommended_action == "ALLOW"
    assert ctx.metadata == {}

