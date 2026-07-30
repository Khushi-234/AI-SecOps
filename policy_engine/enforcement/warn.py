"""
WARN Enforcement Action Implementation.

Allows prompt processing while attaching security warning telemetry for SIEM monitoring.
"""

from __future__ import annotations

from policy_engine.actions import PolicyAction
from policy_engine.context import RiskContext
from policy_engine.logger import logger
from policy_engine.models import PolicyDecision


class WarnEnforcer:
    """Executes WARN enforcement action."""

    def enforce(
        self, decision: PolicyDecision, context: RiskContext
    ) -> PolicyDecision:
        logger.warning(
            f"[Enforcement WARN] Request {context.request_id} allowed with warning monitoring: {decision.reason}"
        )
        meta = dict(decision.metadata)
        meta["enforcement_status"] = "WARNED"

        return PolicyDecision(
            request_id=decision.request_id or context.request_id,
            action=PolicyAction.WARN,
            is_approved=True,
            final_prompt=context.original_prompt,
            reason=decision.reason,
            risk_score=decision.risk_score,
            rule_triggered=decision.rule_triggered,
            timestamp=decision.timestamp,
            metadata=meta,
        )
