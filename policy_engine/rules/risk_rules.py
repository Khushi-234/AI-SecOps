"""
Risk-Score-Based Policy Decision Rules.
"""

from __future__ import annotations

from policy_engine.actions import PolicyAction
from policy_engine.context import RiskContext
from policy_engine.models import PolicyDecision
from policy_engine.rules.base_rule import BasePolicyRule


class RiskScoreRule(BasePolicyRule):
    """
    Evaluates policy decision based on quantitative risk score ranges [0-100].
      0 - 39  : ALLOW
     40 - 69  : WARN
     70 - 89  : SANITIZE
     90 - 100 : BLOCK
    """

    @property
    def rule_name(self) -> str:
        return "RISK_SCORE_RULE"

    def evaluate(self, context: RiskContext) -> PolicyDecision | None:
        score = context.score_100

        if score >= 90.0:
            return PolicyDecision(
                request_id=context.request_id,
                action=PolicyAction.BLOCK,
                is_approved=False,
                final_prompt=None,
                reason=f"Critical risk score ({score:.1f}/100 >= 90) detected.",
                risk_score=context.risk_score,
                rule_triggered=self.rule_name,
                metadata={"rule": self.rule_name, "score": score},
            )
        elif score >= 70.0:
            return PolicyDecision(
                request_id=context.request_id,
                action=PolicyAction.SANITIZE,
                is_approved=True,
                final_prompt=context.original_prompt,
                reason=f"High risk score ({score:.1f}/100 in range 70-89) requires prompt sanitization.",
                risk_score=context.risk_score,
                rule_triggered=self.rule_name,
                metadata={"rule": self.rule_name, "score": score},
            )
        elif score >= 40.0:
            return PolicyDecision(
                request_id=context.request_id,
                action=PolicyAction.WARN,
                is_approved=True,
                final_prompt=context.original_prompt,
                reason=f"Elevated risk score ({score:.1f}/100 in range 40-69) requires monitoring.",
                risk_score=context.risk_score,
                rule_triggered=self.rule_name,
                metadata={"rule": self.rule_name, "score": score},
            )
        else:
            return PolicyDecision(
                request_id=context.request_id,
                action=PolicyAction.ALLOW,
                is_approved=True,
                final_prompt=context.original_prompt,
                reason=f"Low risk score ({score:.1f}/100 in range 0-39) approved.",
                risk_score=context.risk_score,
                rule_triggered=self.rule_name,
                metadata={"rule": self.rule_name, "score": score},
            )
