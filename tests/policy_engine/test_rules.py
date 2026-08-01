"""
Unit tests for policy rules in policy_engine/rules/.
"""

from __future__ import annotations

from dataclasses import dataclass
import pytest

from policy_engine.actions import PolicyAction
from policy_engine.context import RiskContext
from policy_engine.rules.allow_rules import AllowRule
from policy_engine.rules.risk_rules import RiskScoreRule
from policy_engine.rules.severity_rules import SeverityRule
from policy_engine.rules.threat_rules import ThreatRule


# =============================================================================
# AllowRule Tests
# =============================================================================


def test_allow_rule():
    rule = AllowRule()
    assert rule.rule_name == "ALLOW_RULE"

    ctx = RiskContext(request_id="req-allow", original_prompt="Hello", risk_score=0.10)
    decision = rule.evaluate(ctx)

    assert decision.action == PolicyAction.ALLOW
    assert decision.is_approved is True
    assert decision.rule_triggered == "ALLOW_RULE"


# =============================================================================
# RiskScoreRule Tests
# =============================================================================


def test_risk_score_rule_block():
    rule = RiskScoreRule()
    assert rule.rule_name == "RISK_SCORE_RULE"

    # Score >= 0.75 -> BLOCK
    ctx = RiskContext(request_id="req-score-block", original_prompt="Unsafe prompt", risk_score=0.85)
    decision = rule.evaluate(ctx)
    assert decision is not None
    assert decision.action == PolicyAction.BLOCK
    assert decision.is_approved is False


def test_risk_score_rule_sanitize():
    rule = RiskScoreRule()
    # 0.40 <= Score < 0.75 -> SANITIZE
    ctx = RiskContext(request_id="req-score-san", original_prompt="Semi-unsafe prompt", risk_score=0.50)
    decision = rule.evaluate(ctx)
    assert decision is not None
    assert decision.action == PolicyAction.SANITIZE
    assert decision.is_approved is True


def test_risk_score_rule_warn():
    rule = RiskScoreRule()
    # 0.25 <= Score < 0.40 -> WARN
    ctx = RiskContext(request_id="req-score-warn", original_prompt="Elevated prompt", risk_score=0.30)
    decision = rule.evaluate(ctx)
    assert decision is not None
    assert decision.action == PolicyAction.WARN
    assert decision.is_approved is True


def test_risk_score_rule_allow():
    rule = RiskScoreRule()
    # Score < 0.25 -> ALLOW
    ctx = RiskContext(request_id="req-score-allow", original_prompt="Safe prompt", risk_score=0.10)
    decision = rule.evaluate(ctx)
    assert decision is not None
    assert decision.action == PolicyAction.ALLOW
    assert decision.is_approved is True


def test_risk_score_rule_custom_thresholds():
    from policy_engine.config import ThresholdConfig
    custom_cfg = ThresholdConfig(warn_score_threshold=0.10, sanitize_score_threshold=0.30, block_score_threshold=0.50)
    rule = RiskScoreRule(thresholds=custom_cfg)

    # Score 0.40 is now SANITIZE with custom thresholds (instead of WARN)
    ctx = RiskContext(request_id="req-custom-t", original_prompt="Prompt", risk_score=0.40)
    decision = rule.evaluate(ctx)
    assert decision is not None
    assert decision.action == PolicyAction.SANITIZE

    # Score 0.60 is now BLOCK with custom thresholds (instead of SANITIZE)
    ctx_block = RiskContext(request_id="req-custom-blk", original_prompt="Prompt", risk_score=0.60)
    dec_block = rule.evaluate(ctx_block)
    assert dec_block is not None
    assert dec_block.action == PolicyAction.BLOCK


# =============================================================================
# SeverityRule Tests
# =============================================================================


def test_severity_rule_tiers():
    rule = SeverityRule()
    assert rule.rule_name == "SEVERITY_LEVEL_RULE"

    # CRITICAL -> BLOCK
    ctx_crit = RiskContext(request_id="r1", original_prompt="p", risk_level="CRITICAL")
    dec_crit = rule.evaluate(ctx_crit)
    assert dec_crit is not None
    assert dec_crit.action == PolicyAction.BLOCK
    assert dec_crit.is_approved is False

    # HIGH -> SANITIZE
    ctx_high = RiskContext(request_id="r2", original_prompt="p", risk_level="HIGH")
    dec_high = rule.evaluate(ctx_high)
    assert dec_high is not None
    assert dec_high.action == PolicyAction.SANITIZE

    # MEDIUM / MONITOR / WARN -> WARN
    for lvl in ("MEDIUM", "WARN", "MONITOR"):
        ctx_med = RiskContext(request_id="r3", original_prompt="p", risk_level=lvl)
        dec_med = rule.evaluate(ctx_med)
        assert dec_med is not None
        assert dec_med.action == PolicyAction.WARN

    # LOW -> ALLOW
    ctx_low = RiskContext(request_id="r4", original_prompt="p", risk_level="LOW")
    dec_low = rule.evaluate(ctx_low)
    assert dec_low is not None
    assert dec_low.action == PolicyAction.ALLOW

    # UNKNOWN -> None
    ctx_unk = RiskContext(request_id="r5", original_prompt="p", risk_level="UNKNOWN_TIER")
    assert rule.evaluate(ctx_unk) is None


# =============================================================================
# ThreatRule Tests
# =============================================================================


@dataclass
class FindingStub:
    finding_type: str


def test_threat_rule_matching():
    rule = ThreatRule()
    assert rule.rule_name == "THREAT_RULE"

    # Match in detected_threats
    ctx_threat = RiskContext(
        request_id="req-t1",
        original_prompt="Attempting jailbreak",
        detected_threats=("credential_leak", "pii_exposure"),
    )
    dec_threat = rule.evaluate(ctx_threat)
    assert dec_threat is not None
    assert dec_threat.action == PolicyAction.BLOCK
    assert dec_threat.is_approved is False
    assert "credential_leak" in dec_threat.metadata["matched_threats"]

    # Match in evidence finding_type
    ctx_ev = RiskContext(
        request_id="req-t2",
        original_prompt="Attempting prompt injection",
        evidence=(FindingStub(finding_type="secret_exposure"),),
    )
    dec_ev = rule.evaluate(ctx_ev)
    assert dec_ev is not None
    assert dec_ev.action == PolicyAction.BLOCK

    # Partial / Substring threat match
    ctx_sub = RiskContext(
        request_id="req-t3",
        original_prompt="Extending system prompt",
        detected_threats=("system_prompt_extraction_v2",),
    )
    dec_sub = rule.evaluate(ctx_sub)
    assert dec_sub is not None
    assert dec_sub.action == PolicyAction.BLOCK

    # No threat match -> None
    ctx_clean = RiskContext(
        request_id="req-t4",
        original_prompt="Normal prompt",
        detected_threats=("benign_query",),
    )
    assert rule.evaluate(ctx_clean) is None


def test_threat_rule_custom_critical_threats():
    rule = ThreatRule(critical_threats=["custom_sql_injection"])
    assert "custom_sql_injection" in rule.critical_threats

    ctx_custom = RiskContext(
        request_id="req-sql",
        original_prompt="SQL attempt",
        detected_threats=("custom_sql_injection",),
    )
    decision = rule.evaluate(ctx_custom)
    assert decision is not None
    assert decision.action == PolicyAction.BLOCK

