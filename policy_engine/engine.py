"""
PolicyEngine Facade — Core Main Orchestrator.

Decides security action based on RiskContext:
  RiskContext -> Policy Evaluator -> PolicyDecision -> Enforcement Layer -> Final Output
"""

from __future__ import annotations

import logging
import time
from typing import Any, Sequence

from policy_engine.actions import PolicyAction
from policy_engine.config import PolicyEngineConfig
from policy_engine.context import RiskContext
from policy_engine.enforcement import EnforcementLayer
from policy_engine.evaluator import PolicyEvaluator
from policy_engine.exceptions import (
    InvalidPolicyInputError,
    PolicyExecutionError,
)
from policy_engine.models import PolicyDecision
from policy_engine.rules.base_rule import BasePolicyRule
from policy_engine.sanitizers.pipeline import SanitizationPipeline

logger = logging.getLogger(__name__)


class PolicyEngine:
    """
    Main Policy Engine orchestrator.

    Coordinates rule-based evaluation (PolicyEvaluator) and action enforcement (EnforcementLayer)
    to produce deterministic PolicyDecision outputs.
    """

    def __init__(
        self,
        config: PolicyEngineConfig | None = None,
        evaluator: PolicyEvaluator | None = None,
        enforcer: EnforcementLayer | None = None,
        rules: Sequence[BasePolicyRule] | None = None,
        sanitization_pipeline: SanitizationPipeline | None = None,
    ) -> None:
        """
        Initializes PolicyEngine with configuration, evaluator, and enforcement layer.
        """
        self._config = config or PolicyEngineConfig()
        self._evaluator = evaluator or PolicyEvaluator(rules=rules)
        self._enforcer = enforcer or EnforcementLayer(
            sanitization_pipeline=sanitization_pipeline,
            sanitization_config=self._config.sanitization,
        )

    @property
    def config(self) -> PolicyEngineConfig:
        """Returns active PolicyEngineConfig."""
        return self._config

    @property
    def evaluator(self) -> PolicyEvaluator:
        """Returns active PolicyEvaluator."""
        return self._evaluator

    @property
    def enforcer(self) -> EnforcementLayer:
        """Returns active EnforcementLayer."""
        return self._enforcer

    def evaluate(self, context: RiskContext) -> PolicyDecision:
        """
        Main pipeline entry point:
        RiskContext -> PolicyEvaluator -> PolicyDecision -> EnforcementLayer -> Final Output

        Args:
            context: Input RiskContext instance.

        Returns:
            Final enforced PolicyDecision object.

        Raises:
            InvalidPolicyInputError: If context is invalid.
            PolicyExecutionError: If execution fails and strict_fail_secure is False.
        """
        if not isinstance(context, RiskContext):
            raise InvalidPolicyInputError(
                f"Expected RiskContext instance, got {type(context)}"
            )

        start_time = time.perf_counter()

        try:
            # 1. Decision Layer: Evaluate rules and resolve action priority
            raw_decision = self._evaluator.evaluate(context)

            # 2. Enforcement Layer: Execute decided action (Allow, Warn, Sanitize, Block)
            final_decision = self._enforcer.enforce(raw_decision, context)

            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            # Attach execution telemetry to metadata
            meta = dict(final_decision.metadata)
            meta["execution_time_ms"] = elapsed_ms
            meta["risk_score"] = context.risk_score
            meta["score_100"] = context.score_100

            return PolicyDecision(
                request_id=final_decision.request_id or context.request_id,
                action=final_decision.action,
                is_approved=final_decision.is_approved,
                final_prompt=final_decision.final_prompt,
                applied_sanitizations=final_decision.applied_sanitizations,
                reason=final_decision.reason,
                risk_score=final_decision.risk_score,
                rule_triggered=final_decision.rule_triggered,
                timestamp=final_decision.timestamp,
                metadata=meta,
            )

        except Exception as exc:
            logger.error("Unhandled error during PolicyEngine pipeline execution: %s", exc, exc_info=True)
            if self._config.strict_fail_secure:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                return PolicyDecision(
                    request_id=context.request_id,
                    action=PolicyAction.BLOCK,
                    is_approved=False,
                    final_prompt=None,
                    reason=f"Fail-secure enforcement BLOCKED request due to error: {exc}",
                    risk_score=context.risk_score,
                    rule_triggered="FAIL_SECURE_ERROR",
                    metadata={"error": str(exc), "execution_time_ms": elapsed_ms},
                )
            raise PolicyExecutionError(
                message=f"PolicyEngine execution failed: {exc}",
                cause=exc,
            ) from exc

    def evaluate_from_risk_response(
        self,
        request_id: str,
        original_prompt: str,
        risk_response: Any,
        metadata: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """
        Convenience method building a RiskContext directly from a RiskEngineResponse,
        RiskAssessment, or dictionary payload before evaluating.
        """
        context = RiskContext.from_risk_response(
            request_id=request_id,
            original_prompt=original_prompt,
            risk_response=risk_response,
            metadata=metadata,
        )
        return self.evaluate(context)
