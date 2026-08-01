"""
Risk-Score-Based Policy Decision Rules.
"""

from __future__ import annotations

from policy_engine.actions import PolicyAction
from policy_engine.config import ThresholdConfig
from policy_engine.context import RiskContext
from policy_engine.models import PolicyDecision
from policy_engine.rules.base_rule import BasePolicyRule


class RiskScoreRule(BasePolicyRule):
    """
    Evaluates policy decision based on configurable quantitative risk score boundary thresholds.
    """

    def __init__(self, thresholds: ThresholdConfig | None = None) -> None:
        """Initializes RiskScoreRule with configurable thresholds or defaults."""
        self._thresholds = thresholds or ThresholdConfig()

    @property
    def thresholds(self) -> ThresholdConfig:
        """Returns configured ThresholdConfig."""
        return self._thresholds

    @property
    def rule_name(self) -> str:
        return "RISK_SCORE_RULE"

    def evaluate(self, context: RiskContext) -> PolicyDecision | None:
        score = context.composite_score
        score_100 = context.score_100

        if score >= self._thresholds.block_score_threshold:
            return PolicyDecision(
                request_id=context.request_id,
                action=PolicyAction.BLOCK,
                is_approved=False,
                reason=f"Risk score ({score:.2f} / {score_100:.1f}) exceeds block threshold ({self._thresholds.block_score_threshold:.2f}).",
                risk_score=context.risk_score,
                rule_triggered=self.rule_name,
                metadata={"rule": self.rule_name, "score": score, "threshold": self._thresholds.block_score_threshold},
            )
        elif score >= self._thresholds.sanitize_score_threshold:
            return PolicyDecision(
                request_id=context.request_id,
                action=PolicyAction.SANITIZE,
                is_approved=True,
                reason=f"Risk score ({score:.2f} / {score_100:.1f}) exceeds sanitize threshold ({self._thresholds.sanitize_score_threshold:.2f}).",
                risk_score=context.risk_score,
                rule_triggered=self.rule_name,
                metadata={"rule": self.rule_name, "score": score, "threshold": self._thresholds.sanitize_score_threshold},
            )
        elif score >= self._thresholds.warn_score_threshold:
            return PolicyDecision(
                request_id=context.request_id,
                action=PolicyAction.WARN,
                is_approved=True,
                reason=f"Risk score ({score:.2f} / {score_100:.1f}) exceeds warn threshold ({self._thresholds.warn_score_threshold:.2f}).",
                risk_score=context.risk_score,
                rule_triggered=self.rule_name,
                metadata={"rule": self.rule_name, "score": score, "threshold": self._thresholds.warn_score_threshold},
            )
        else:
            return PolicyDecision(
                request_id=context.request_id,
                action=PolicyAction.ALLOW,
                is_approved=True,
                reason=f"Risk score ({score:.2f} / {score_100:.1f}) below warn threshold ({self._thresholds.warn_score_threshold:.2f}).",
                risk_score=context.risk_score,
                rule_triggered=self.rule_name,
                metadata={"rule": self.rule_name, "score": score, "threshold": self._thresholds.warn_score_threshold},
            )

