"""
Severity-Level-Based Policy Decision Rules.
"""

from __future__ import annotations

from policy_engine.actions import PolicyAction
from policy_engine.context import RiskContext
from policy_engine.models import PolicyDecision
from policy_engine.rules.base_rule import BasePolicyRule


class SeverityRule(BasePolicyRule):
    """
    Evaluates policy decision based on qualitative risk level tier (CRITICAL, HIGH, MEDIUM, LOW).
    """

    @property
    def rule_name(self) -> str:
        return "SEVERITY_LEVEL_RULE"

    def evaluate(self, context: RiskContext) -> PolicyDecision | None:
        risk_lvl = str(context.risk_level).upper()

        if risk_lvl == "CRITICAL":
            return PolicyDecision(
                request_id=context.request_id,
                action=PolicyAction.BLOCK,
                is_approved=False,
                final_prompt=None,
                reason="CRITICAL risk level tier requires immediate BLOCK enforcement.",
                risk_score=context.risk_score,
                rule_triggered=self.rule_name,
            )
        elif risk_lvl == "HIGH":
            return PolicyDecision(
                request_id=context.request_id,
                action=PolicyAction.SANITIZE,
                is_approved=True,
                final_prompt=context.original_prompt,
                reason="HIGH risk level tier requires prompt SANITIZE enforcement.",
                risk_score=context.risk_score,
                rule_triggered=self.rule_name,
            )
        elif risk_lvl in ("MEDIUM", "WARN", "MONITOR"):
            return PolicyDecision(
                request_id=context.request_id,
                action=PolicyAction.WARN,
                is_approved=True,
                final_prompt=context.original_prompt,
                reason="MEDIUM risk level tier requires WARN monitoring directive.",
                risk_score=context.risk_score,
                rule_triggered=self.rule_name,
            )
        elif risk_lvl == "LOW":
            return PolicyDecision(
                request_id=context.request_id,
                action=PolicyAction.ALLOW,
                is_approved=True,
                final_prompt=context.original_prompt,
                reason="LOW risk level tier approved for normal processing.",
                risk_score=context.risk_score,
                rule_triggered=self.rule_name,
            )

        return None
