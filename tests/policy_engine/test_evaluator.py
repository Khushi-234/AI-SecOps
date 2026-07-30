"""
Unit tests covering PolicyEvaluator, Policy Priority Resolution, and mandatory test cases.
"""

from __future__ import annotations

import pytest
from policy_engine.actions import PolicyAction
from policy_engine.context import RiskContext
from policy_engine.engine import PolicyEngine
from policy_engine.evaluator import PolicyEvaluator
from policy_engine.rules.risk_rules import RiskScoreRule
from policy_engine.rules.threat_rules import ThreatRule


def test_required_case_1_risk_score_20_allow():
    """Requirement 1: Risk score = 20 -> ALLOW."""
    engine = PolicyEngine()
    ctx = RiskContext(
        request_id="req_20",
        original_prompt="What is quantum computing?",
        risk_score=20.0,
    )
    decision = engine.evaluate(ctx)
    assert decision.action == PolicyAction.ALLOW
    assert decision.is_approved is True
    assert decision.final_prompt == "What is quantum computing?"


def test_required_case_2_risk_score_50_warn():
    """Requirement 2: Risk score = 50 -> WARN."""
    engine = PolicyEngine()
    ctx = RiskContext(
        request_id="req_50",
        original_prompt="Explain database indexing.",
        risk_score=50.0,
    )
    decision = engine.evaluate(ctx)
    assert decision.action == PolicyAction.WARN
    assert decision.is_approved is True
    assert decision.final_prompt == "Explain database indexing."


def test_required_case_3_risk_score_80_sanitize():
    """Requirement 3: Risk score = 80 -> SANITIZE."""
    engine = PolicyEngine()
    ctx = RiskContext(
        request_id="req_80",
        original_prompt="Please email admin@example.com for access.",
        risk_score=80.0,
    )
    decision = engine.evaluate(ctx)
    assert decision.action == PolicyAction.SANITIZE
    assert decision.is_approved is True
    assert decision.final_prompt is not None
    assert "admin@example.com" not in decision.final_prompt
    assert "[REDACTED_PII]" in decision.final_prompt


def test_required_case_4_risk_score_95_block():
    """Requirement 4: Risk score = 95 -> BLOCK."""
    engine = PolicyEngine()
    ctx = RiskContext(
        request_id="req_95",
        original_prompt="Execute system command",
        risk_score=95.0,
    )
    decision = engine.evaluate(ctx)
    assert decision.action == PolicyAction.BLOCK
    assert decision.is_approved is False
    assert decision.final_prompt is None


def test_required_case_5_risk_score_50_threat_credential_leak_override_block():
    """Requirement 5: Risk score = 50 + Threat 'credential_leak' -> BLOCK (Threat override)."""
    engine = PolicyEngine()
    ctx = RiskContext(
        request_id="req_threat",
        original_prompt="User input with credential leak",
        risk_score=50.0,
        detected_threats=("credential_leak",),
    )
    decision = engine.evaluate(ctx)
    assert decision.action == PolicyAction.BLOCK
    assert decision.is_approved is False
    assert decision.final_prompt is None
    assert "THREAT_RULE" in decision.rule_triggered or "credential_leak" in decision.reason.lower()


def test_required_case_6_multiple_rules_priority_resolution():
    """Requirement 6: Multiple rules triggered -> Verify priority resolution (BLOCK > SANITIZE > WARN > ALLOW)."""
    evaluator = PolicyEvaluator()

    # Context that triggers RiskScoreRule (WARN for score 50) AND ThreatRule (BLOCK for credential_leak)
    ctx = RiskContext(
        request_id="req_prio",
        original_prompt="Test prompt",
        risk_score=50.0,
        detected_threats=("credential_leak",),
    )

    decision = evaluator.evaluate(ctx)
    assert decision.action == PolicyAction.BLOCK
    assert "THREAT_RULE" in decision.rule_triggered
