"""
ALLOW Enforcement Action Implementation.

Allows prompt processing unchanged.
"""

from __future__ import annotations

from policy_engine.actions import PolicyAction
from policy_engine.context import RiskContext
from policy_engine.models import PolicyDecision


class AllowEnforcer:
    """Executes ALLOW enforcement action."""

    def enforce(
        self, decision: PolicyDecision, context: RiskContext
    ) -> PolicyDecision:
        return PolicyDecision(
            request_id=decision.request_id or context.request_id,
            action=PolicyAction.ALLOW,
            is_approved=True,
            reason=decision.reason,
            risk_score=decision.risk_score,
            rule_triggered=decision.rule_triggered,
            timestamp=decision.timestamp,
            metadata=decision.metadata,
            matched_rules=decision.matched_rules,
        )

