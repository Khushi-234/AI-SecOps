"""
BLOCK Enforcement Action Implementation.

Stops request execution completely and prevents prompt processing.
"""

from __future__ import annotations

from policy_engine.actions import PolicyAction
from policy_engine.context import RiskContext
from policy_engine.logger import logger
from policy_engine.models import PolicyDecision


class BlockEnforcer:
    """Executes BLOCK enforcement action."""

    def enforce(
        self, decision: PolicyDecision, context: RiskContext
    ) -> PolicyDecision:
        logger.warning(
            f"[Enforcement BLOCK] Request {context.request_id} BLOCKED: {decision.reason}"
        )
        meta = dict(decision.metadata)
        meta["enforcement_status"] = "BLOCKED"

        return PolicyDecision(
            request_id=decision.request_id or context.request_id,
            action=PolicyAction.BLOCK,
            is_approved=False,
            final_prompt=None,
            reason=decision.reason,
            risk_score=decision.risk_score,
            rule_triggered=decision.rule_triggered,
            timestamp=decision.timestamp,
            metadata=meta,
        )
