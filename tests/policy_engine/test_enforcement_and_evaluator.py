"""
Unit tests for enforcement layer and evaluator in policy_engine.
"""

from __future__ import annotations

import pytest

from policy_engine.actions import PolicyAction
from policy_engine.context import RiskContext
from policy_engine.enforcement import EnforcementLayer
from policy_engine.enforcement.allow import AllowEnforcer
from policy_engine.enforcement.block import BlockEnforcer
from policy_engine.enforcement.sanitize import SanitizeEnforcer
from policy_engine.enforcement.warn import WarnEnforcer
from policy_engine.evaluator import PolicyEvaluator
from policy_engine.models import PolicyDecision
from policy_engine.rules.base_rule import BasePolicyRule


# =============================================================================
# Individual Enforcer Tests
# =============================================================================


def test_allow_enforcer():
    enforcer = AllowEnforcer()
    ctx = RiskContext(request_id="req-allow", original_prompt="Original Prompt text")
    dec = PolicyDecision(action=PolicyAction.ALLOW, reason="Approved", request_id="req-allow")

    res = enforcer.enforce(dec, ctx)

    assert res.action == PolicyAction.ALLOW
    assert res.is_approved is True
    assert res.final_prompt == "Original Prompt text"


def test_warn_enforcer():
    enforcer = WarnEnforcer()
    ctx = RiskContext(request_id="req-warn", original_prompt="Prompt under monitoring")
    dec = PolicyDecision(action=PolicyAction.WARN, reason="Elevated risk", request_id="req-warn")

    res = enforcer.enforce(dec, ctx)

    assert res.action == PolicyAction.WARN
    assert res.is_approved is True
    assert res.final_prompt == "Prompt under monitoring"
    assert res.metadata.get("enforcement_status") == "WARNED"


def test_sanitize_enforcer():
    enforcer = SanitizeEnforcer()
    ctx = RiskContext(request_id="req-san", original_prompt="Email: user@example.com")
    dec = PolicyDecision(action=PolicyAction.SANITIZE, reason="PII present", request_id="req-san")

    res = enforcer.enforce(dec, ctx)

    assert res.action == PolicyAction.SANITIZE
    assert res.is_approved is True
    assert res.final_prompt is not None
    assert "user@example.com" not in res.final_prompt
    assert len(res.applied_sanitizations) > 0
    assert "sanitization_processing_time_ms" in res.metadata


def test_block_enforcer():
    enforcer = BlockEnforcer()
    ctx = RiskContext(request_id="req-block", original_prompt="Dangerous prompt")
    dec = PolicyDecision(action=PolicyAction.BLOCK, reason="Jailbreak detected", request_id="req-block")

    res = enforcer.enforce(dec, ctx)

    assert res.action == PolicyAction.BLOCK
    assert res.is_approved is False
    assert res.final_prompt is None
    assert res.metadata.get("enforcement_status") == "BLOCKED"


# =============================================================================
# EnforcementLayer Dispatcher Tests
# =============================================================================


def test_enforcement_layer_dispatching():
    layer = EnforcementLayer()
    ctx = RiskContext(request_id="req-disp", original_prompt="Prompt with secret AKIA1234567890ABCDEF")

    # BLOCK dispatch
    dec_b = PolicyDecision(action=PolicyAction.BLOCK, reason="Block reason")
    res_b = layer.enforce(dec_b, ctx)
    assert res_b.action == PolicyAction.BLOCK

    # SANITIZE dispatch
    dec_s = PolicyDecision(action=PolicyAction.SANITIZE, reason="Sanitize reason")
    res_s = layer.enforce(dec_s, ctx)
    assert res_s.action == PolicyAction.SANITIZE

    # WARN dispatch
    dec_w = PolicyDecision(action=PolicyAction.WARN, reason="Warn reason")
    res_w = layer.enforce(dec_w, ctx)
    assert res_w.action == PolicyAction.WARN

    # ALLOW dispatch
    dec_a = PolicyDecision(action=PolicyAction.ALLOW, reason="Allow reason")
    res_a = layer.enforce(dec_a, ctx)
    assert res_a.action == PolicyAction.ALLOW


# =============================================================================
# PolicyEvaluator Priority & Evaluation Tests
# =============================================================================


class StubRule(BasePolicyRule):

    def __init__(self, name: str, action: PolicyAction):
        self._name = name
        self._action = action

    @property
    def rule_name(self) -> str:
        return self._name

    def evaluate(self, context: RiskContext) -> PolicyDecision | None:
        return PolicyDecision(
            request_id=context.request_id,
            action=self._action,
            reason=f"Triggered by {self._name}",
            rule_triggered=self._name,
        )


def test_evaluator_priority_resolution():
    # Register rules returning WARN, BLOCK, and SANITIZE
    rule_warn = StubRule("RULE_WARN", PolicyAction.WARN)
    rule_block = StubRule("RULE_BLOCK", PolicyAction.BLOCK)
    rule_san = StubRule("RULE_SAN", PolicyAction.SANITIZE)

    evaluator = PolicyEvaluator(rules=[rule_warn, rule_san, rule_block])
    ctx = RiskContext(request_id="req-eval-prio", original_prompt="Prompt text")

    # Highest priority action (BLOCK) must win regardless of order
    decision = evaluator.evaluate(ctx)
    assert decision.action == PolicyAction.BLOCK
    assert decision.rule_triggered == "RULE_BLOCK"


def test_evaluator_default_fallback():
    evaluator = PolicyEvaluator(rules=[])
    ctx = RiskContext(request_id="req-empty-rules", original_prompt="Prompt")

    decision = evaluator.evaluate(ctx)
    assert decision.action == PolicyAction.ALLOW
    assert decision.rule_triggered == "DEFAULT_ALLOW"


def test_evaluator_get_action_priority():
    assert PolicyEvaluator._get_action_priority(PolicyAction.BLOCK) == 4
    assert PolicyEvaluator._get_action_priority("SANITIZE") == 3
    assert PolicyEvaluator._get_action_priority("WARN") == 2
    assert PolicyEvaluator._get_action_priority("ALLOW") == 1
    assert PolicyEvaluator._get_action_priority("INVALID_ACTION") == 1
