"""
Unit tests for PolicyEngine main orchestrator facade in policy_engine/engine.py.
"""

from __future__ import annotations

from unittest.mock import MagicMock
import pytest

from policy_engine.actions import PolicyAction
from policy_engine.config import PolicyEngineConfig
from policy_engine.context import RiskContext
from policy_engine.engine import PolicyEngine
from policy_engine.enforcement import EnforcementLayer
from policy_engine.evaluator import PolicyEvaluator
from policy_engine.exceptions import InvalidPolicyInputError, PolicyExecutionError
from policy_engine.models import PolicyDecision


def test_policy_engine_initialization_defaults():
    engine = PolicyEngine()
    assert isinstance(engine.config, PolicyEngineConfig)
    assert isinstance(engine.evaluator, PolicyEvaluator)
    assert isinstance(engine.enforcer, EnforcementLayer)


def test_policy_engine_custom_initialization():
    custom_cfg = PolicyEngineConfig(strict_fail_secure=False)
    evaluator = PolicyEvaluator(rules=[])
    enforcer = EnforcementLayer()

    engine = PolicyEngine(config=custom_cfg, evaluator=evaluator, enforcer=enforcer)
    assert engine.config.strict_fail_secure is False
    assert engine.evaluator == evaluator
    assert engine.enforcer == enforcer


def test_policy_engine_evaluate_invalid_context():
    engine = PolicyEngine()
    with pytest.raises(InvalidPolicyInputError, match="Expected RiskContext instance"):
        engine.evaluate("not a risk context")  # type: ignore


def test_policy_engine_evaluate_allow_flow():
    engine = PolicyEngine()
    ctx = RiskContext(request_id="req-pe-allow", original_prompt="Safe input prompt", risk_score=0.10)

    decision = engine.evaluate(ctx)

    assert decision.request_id == "req-pe-allow"
    assert decision.action == PolicyAction.ALLOW
    assert decision.is_approved is True
    assert decision.final_prompt == "Safe input prompt"
    assert "execution_time_ms" in decision.metadata
    assert decision.metadata["risk_score"] == 0.10
    assert decision.metadata["score_100"] == 10.0


def test_policy_engine_evaluate_sanitize_flow():
    engine = PolicyEngine()
    ctx = RiskContext(
        request_id="req-pe-san",
        original_prompt="Contact alice@corp.com or use AKIA1234567890ABCDEF",
        risk_score=0.75,
    )

    decision = engine.evaluate(ctx)

    assert decision.action == PolicyAction.SANITIZE
    assert decision.is_approved is True
    assert decision.final_prompt is not None
    assert "alice@corp.com" not in decision.final_prompt
    assert "AKIA1234567890ABCDEF" not in decision.final_prompt
    assert len(decision.applied_sanitizations) >= 2


def test_policy_engine_evaluate_block_flow():
    engine = PolicyEngine()
    ctx = RiskContext(
        request_id="req-pe-block",
        original_prompt="Attempting system prompt extraction and jailbreak",
        detected_threats=("jailbreak", "credential_leak"),
        risk_score=0.95,
    )

    decision = engine.evaluate(ctx)

    assert decision.action == PolicyAction.BLOCK
    assert decision.is_approved is False
    assert decision.final_prompt is None
    assert decision.rule_triggered in ("THREAT_RULE", "RISK_SCORE_RULE")


def test_policy_engine_strict_fail_secure_true():
    mock_evaluator = MagicMock(spec=PolicyEvaluator)
    mock_evaluator.evaluate.side_effect = RuntimeError("Database connection crashed")

    cfg = PolicyEngineConfig(strict_fail_secure=True)
    engine = PolicyEngine(config=cfg, evaluator=mock_evaluator)

    ctx = RiskContext(request_id="req-fail-sec", original_prompt="Some prompt", risk_score=0.20)

    # Should handle exception and return fail-secure BLOCK decision
    decision = engine.evaluate(ctx)

    assert decision.request_id == "req-fail-sec"
    assert decision.action == PolicyAction.BLOCK
    assert decision.is_approved is False
    assert decision.final_prompt is None
    assert decision.rule_triggered == "FAIL_SECURE_ERROR"
    assert "Database connection crashed" in decision.reason
    assert "error" in decision.metadata


def test_policy_engine_strict_fail_secure_false():
    mock_evaluator = MagicMock(spec=PolicyEvaluator)
    mock_evaluator.evaluate.side_effect = RuntimeError("Database connection crashed")

    cfg = PolicyEngineConfig(strict_fail_secure=False)
    engine = PolicyEngine(config=cfg, evaluator=mock_evaluator)

    ctx = RiskContext(request_id="req-fail-raise", original_prompt="Some prompt", risk_score=0.20)

    # Should raise PolicyExecutionError
    with pytest.raises(PolicyExecutionError, match="PolicyEngine execution failed"):
        engine.evaluate(ctx)


def test_policy_engine_evaluate_from_risk_response():
    engine = PolicyEngine()

    risk_dict = {
        "risk_score": 0.85,
        "confidence_score": 0.90,
        "detected_threats": ["secret_leak"],
        "risk_level": "HIGH",
        "recommended_action": "SANITIZE",
    }

    decision = engine.evaluate_from_risk_response(
        request_id="req-resp-conv",
        original_prompt="User key AKIA1234567890ABCDEF",
        risk_response=risk_dict,
    )

    assert decision.request_id == "req-resp-conv"
    assert decision.action in (PolicyAction.BLOCK, PolicyAction.SANITIZE)
