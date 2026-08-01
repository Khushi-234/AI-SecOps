"""
Unit tests for config, context, and models modules in policy_engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from enum import Enum
from typing import Any
import pytest

from policy_engine.actions import PolicyAction
from policy_engine.config import PolicyEngineConfig, ThresholdConfig
from policy_engine.context import RiskContext
from policy_engine.exceptions import InvalidPolicyInputError, PolicyConfigurationError
from policy_engine.models import PolicyDecision



# =============================================================================
# Configuration Tests
# =============================================================================


def test_threshold_config_defaults():
    cfg = ThresholdConfig()
    assert cfg.block_score_threshold == 0.75
    assert cfg.sanitize_score_threshold == 0.40
    assert cfg.warn_score_threshold == 0.25


def test_threshold_config_invalid_boundaries():
    with pytest.raises(PolicyConfigurationError, match="must be between 0.0 and 1.0"):
        ThresholdConfig(block_score_threshold=1.5)

    with pytest.raises(PolicyConfigurationError, match="must be between 0.0 and 1.0"):
        ThresholdConfig(warn_score_threshold=-0.1)


def test_threshold_config_invalid_ordering():
    with pytest.raises(PolicyConfigurationError, match="Invalid threshold ordering"):
        ThresholdConfig(warn_score_threshold=0.8, sanitize_score_threshold=0.5, block_score_threshold=0.9)


def test_policy_engine_config_to_dict():
    cfg = PolicyEngineConfig()
    d = cfg.to_dict()

    assert d["thresholds"]["block_score_threshold"] == 0.75
    assert "critical_threats" in d
    assert "credential_leak" in d["critical_threats"]
    assert d["strict_fail_secure"] is True
    assert d["default_action"] == "WARN"


# =============================================================================
# RiskContext Tests
# =============================================================================


def test_risk_context_post_init_validation():
    with pytest.raises(InvalidPolicyInputError, match="risk_score must be non-negative"):
        RiskContext(request_id="req-1", original_prompt="test", risk_score=-1.0)

    # Conversion of lists to tuples
    ctx = RiskContext(
        request_id="req-1",
        original_prompt="test",
        detected_threats=("jailbreak", "pii"),  # tuple
        evidence=("finding1",),  # tuple
    )
    assert isinstance(ctx.detected_threats, tuple)
    assert ctx.detected_threats == ("jailbreak", "pii")
    assert isinstance(ctx.evidence, tuple)
    assert ctx.evidence == ("finding1",)


def test_risk_context_score_properties():
    # 0.0 - 1.0 scale
    ctx1 = RiskContext(request_id="r1", original_prompt="p", risk_score=0.85)
    assert ctx1.score_100 == 85.0
    assert ctx1.composite_score == 0.85

    # 0 - 100 scale
    ctx2 = RiskContext(request_id="r2", original_prompt="p", risk_score=85.0)
    assert ctx2.score_100 == 85.0
    assert ctx2.composite_score == 0.85

    # 0.0 score edge case
    ctx3 = RiskContext(request_id="r3", original_prompt="p", risk_score=0.0)
    assert ctx3.score_100 == 0.0
    assert ctx3.composite_score == 0.0


def test_risk_context_to_dict():
    ctx = RiskContext(
        request_id="req-123",
        original_prompt="Hello world",
        risk_score=0.75,
        detected_threats=("credential_leak",),
        risk_level="HIGH",
        recommended_action="BLOCK",
        metadata={"client": "test_app"},
    )
    d = ctx.to_dict()
    assert d["request_id"] == "req-123"
    assert d["original_prompt"] == "Hello world"
    assert d["score_100"] == 75.0
    assert d["composite_score"] == 0.75
    assert d["detected_threats"] == ["credential_leak"]
    assert d["metadata"] == {"client": "test_app"}


class DummyEnumAction(Enum):
    BLOCK = "BLOCK"


class DummyEnumLevel(Enum):
    HIGH = "HIGH"


@dataclass
class DummyFinding:
    finding_type: str = "credential_leak"


@dataclass
class DummyAssessment:
    composite_score: float = 0.80
    confidence_score: float = 0.95
    risk_level: Any = DummyEnumLevel.HIGH
    evidence: tuple = (DummyFinding(),)
    metadata: dict | None = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {"scoring_model": "weighted"}


@dataclass
class DummyRecommendation:
    action: Any = DummyEnumAction.BLOCK


@dataclass
class DummyRiskResponse:
    assessment: DummyAssessment = field(default_factory=DummyAssessment)
    recommendation: DummyRecommendation = field(default_factory=DummyRecommendation)


def test_risk_context_from_risk_response_object():
    resp = DummyRiskResponse()
    ctx = RiskContext.from_risk_response("req-obj", "Test prompt", resp)

    assert ctx.request_id == "req-obj"
    assert ctx.original_prompt == "Test prompt"
    assert ctx.risk_score == 0.80
    assert ctx.detected_threats == ("credential_leak",)
    assert ctx.risk_level == "HIGH"
    assert ctx.recommended_action == "BLOCK"
    assert ctx.metadata["scoring_model"] == "weighted"


def test_risk_context_from_risk_assessment_object():
    assess = DummyAssessment()
    ctx = RiskContext.from_risk_response("req-assess", "Test prompt 2", assess)

    assert ctx.request_id == "req-assess"
    assert ctx.risk_score == 0.80
    assert ctx.detected_threats == ("credential_leak",)


def test_risk_context_from_risk_response_dict():
    dict_payload = {
        "risk_score": 0.50,
        "confidence_score": 0.90,
        "detected_threats": ["pii_leak"],
        "risk_level": "MEDIUM",
        "recommended_action": "WARN",
        "metadata": {"source": "validator"},
    }
    ctx = RiskContext.from_risk_response("req-dict", "Prompt string", dict_payload)

    assert ctx.request_id == "req-dict"
    assert ctx.risk_score == 0.50
    assert ctx.detected_threats == ("pii_leak",)
    assert ctx.risk_level == "MEDIUM"
    assert ctx.recommended_action == "WARN"


def test_risk_context_from_risk_response_unsupported():
    with pytest.raises(InvalidPolicyInputError, match="Unsupported risk_response payload type"):
        RiskContext.from_risk_response("r", "p", 12345)


# =============================================================================
# Models Tests
# =============================================================================


def test_policy_decision_validation_and_to_dict():
    # String action parsing & BLOCK enforcement
    dec_block = PolicyDecision(
        action="BLOCK",
        reason="Jailbreak detected",
        risk_score=0.95,
        rule_triggered="THREAT_RULE",
        request_id="req-blk",
        matched_rules=("THREAT_RULE", "RISK_SCORE_RULE"),
    )

    assert dec_block.action == PolicyAction.BLOCK
    assert dec_block.is_approved is False
    assert dec_block.matched_rules == ("THREAT_RULE", "RISK_SCORE_RULE")

    d = dec_block.to_dict()
    assert d["request_id"] == "req-blk"
    assert d["action"] == "BLOCK"
    assert d["is_approved"] is False
    assert d["rule_triggered"] == "THREAT_RULE"
    assert d["matched_rules"] == ["THREAT_RULE", "RISK_SCORE_RULE"]
    assert "timestamp" in d

