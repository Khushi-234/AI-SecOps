"""
SANITIZE Enforcement Action Implementation.

Executes prompt sanitization pipeline to redact unsafe components (PII, secrets, control tags)
and returns an approved sanitized prompt stream.
"""

from __future__ import annotations

from policy_engine.actions import PolicyAction
from policy_engine.config import SanitizationConfig
from policy_engine.context import RiskContext
from policy_engine.models import PolicyDecision
from policy_engine.sanitizers.pipeline import SanitizationPipeline


class SanitizeEnforcer:
    """Executes SANITIZE enforcement action using SanitizationPipeline."""

    def __init__(
        self, pipeline: SanitizationPipeline | None = None, config: SanitizationConfig | None = None
    ) -> None:
        self._pipeline = pipeline or SanitizationPipeline(config=config)

    def enforce(
        self, decision: PolicyDecision, context: RiskContext
    ) -> PolicyDecision:
        sanitization_result = self._pipeline.execute(
            context.original_prompt, context=context
        )

        meta = dict(decision.metadata)
        meta["sanitization_processing_time_ms"] = sanitization_result.processing_time_ms
        meta["applied_edit_count"] = len(sanitization_result.edits)

        return PolicyDecision(
            request_id=decision.request_id or context.request_id,
            action=PolicyAction.SANITIZE,
            is_approved=True,
            final_prompt=sanitization_result.sanitized_prompt,
            applied_sanitizations=sanitization_result.edits,
            reason=decision.reason,
            risk_score=decision.risk_score,
            rule_triggered=decision.rule_triggered,
            timestamp=decision.timestamp,
            metadata=meta,
        )
