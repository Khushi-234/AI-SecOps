"""
Default Allow Policy Decision Rule.
"""

from __future__ import annotations

from policy_engine.actions import PolicyAction
from policy_engine.context import RiskContext
from policy_engine.models import PolicyDecision
from policy_engine.rules.base_rule import BasePolicyRule


class AllowRule(BasePolicyRule):
    """
    Default rule approving normal processing for requests.
    """

    @property
    def rule_name(self) -> str:
        return "ALLOW_RULE"

    def evaluate(self, context: RiskContext) -> PolicyDecision:
        return PolicyDecision(
            request_id=context.request_id,
            action=PolicyAction.ALLOW,
            is_approved=True,
            final_prompt=context.original_prompt,
            reason=f"Request approved with ALLOW action (Composite score: {context.composite_score:.2f}).",
            risk_score=context.risk_score,
            rule_triggered=self.rule_name,
            metadata={"rule": self.rule_name, "score": context.composite_score},
        )
