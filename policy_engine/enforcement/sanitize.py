"""
SANITIZE Enforcement Action Implementation.

Marks request as requiring downstream SANITIZE action by Prompt Hardener.
"""

from __future__ import annotations

from policy_engine.actions import PolicyAction
from policy_engine.context import RiskContext
from policy_engine.logger import logger
from policy_engine.models import PolicyDecision


class SanitizeEnforcer:
    """Executes SANITIZE enforcement decision directive."""

    def enforce(
        self, decision: PolicyDecision, context: RiskContext
    ) -> PolicyDecision:
        logger.info(
            f"[Enforcement SANITIZE] Request {context.request_id} approved with SANITIZE directive: {decision.reason}"
        )
        meta = dict(decision.metadata)
        meta["enforcement_status"] = "SANITIZE_REQUIRED"

        return PolicyDecision(
            request_id=decision.request_id or context.request_id,
            action=PolicyAction.SANITIZE,
            is_approved=True,
            reason=decision.reason,
            risk_score=decision.risk_score,
            rule_triggered=decision.rule_triggered,
            timestamp=decision.timestamp,
            metadata=meta,
            matched_rules=decision.matched_rules,
        )

