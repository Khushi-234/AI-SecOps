"""
Policy Evaluation Rules for the Policy Engine.

Provides deterministic rule components for assessing RiskContext and dispatching
actions (ALLOW, WARN, SANITIZE, BLOCK).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from policy_engine.config import PolicyEngineConfig
from policy_engine.actions import PolicyAction
from policy_engine.models import PolicyDecision, RiskContext, SanitizationResult
from policy_engine.sanitizers.pipeline import SanitizationPipeline


class BasePolicyRule(ABC):
    """
    Abstract base class for policy rules.
    """

    @abstractmethod
    def evaluate(
        self,
        context: RiskContext,
        config: PolicyEngineConfig,
        sanitization_pipeline: SanitizationPipeline,
    ) -> PolicyDecision | None:
        """
        Evaluates a RiskContext payload against rule criteria.

        Args:
            context: Input RiskContext object.
            config: PolicyEngineConfig configuration instance.
            sanitization_pipeline: SanitizationPipeline instance.

        Returns:
            PolicyDecision if rule triggers, otherwise None.
        """
        pass


class CriticalBlockRule(BasePolicyRule):
    """
    Blocks requests exceeding block risk thresholds or exhibiting critical security threats.
    """

    def evaluate(
        self,
        context: RiskContext,
        config: PolicyEngineConfig,
        sanitization_pipeline: SanitizationPipeline,
    ) -> PolicyDecision | None:
        block_threshold = config.thresholds.block_score_threshold
        risk_lvl = str(context.risk_level).upper()
        rec_action = str(context.recommended_action).upper()

        # Hard Block Trigger Conditions
        is_blocked = (
            context.composite_score >= block_threshold
            or risk_lvl == "CRITICAL"
            or rec_action == "BLOCK"
        )

        # Check for unrecoverable injection / jailbreak evidence
        if not is_blocked and context.evidence:
            for item in context.evidence:
                finding_type = str(getattr(item, "finding_type", "")).lower()
                sev = str(getattr(item, "severity", "")).upper()
                if ("injection" in finding_type or "jailbreak" in finding_type) and (
                    sev in ("HIGH", "CRITICAL") or getattr(item, "confidence", 0.0) >= 0.7
                ):
                    is_blocked = True
                    break

        if is_blocked:
            reason = (
                f"Security enforcement BLOCKED request (Composite score: {context.composite_score:.2f}, "
                f"Risk level: {context.risk_level}, Recommended action: {context.recommended_action})."
            )
            return PolicyDecision(
                request_id=context.request_id,
                action=PolicyAction.BLOCK,
                is_approved=False,
                final_prompt=None,
                reason=reason,
                metadata ={"rule": "CriticalBlockRule", "score": context.composite_score},
            )

        return None


class SanitizationEligibilityRule(BasePolicyRule):
    """
    Evaluates whether prompt text contains remediable unsafe findings (PII, secrets, control tokens)
    and executes prompt sanitization to generate an approved sanitized prompt flow.
    """

    def evaluate(
        self,
        context: RiskContext,
        config: PolicyEngineConfig,
        sanitization_pipeline: SanitizationPipeline,
    ) -> PolicyDecision | None:
        # Execute pipeline scan to check if prompt requires sanitization
        san_res = sanitization_pipeline.execute(
            context.original_prompt, context=context
        )

        has_edits = len(san_res.edits) > 0
        score_triggers_sanitization = (
            context.composite_score >= config.thresholds.sanitize_score_threshold
        )

        if has_edits or (score_triggers_sanitization and context.evidence):
            reason = (
                f"Request approved with SANITIZE action. Applied {len(san_res.edits)} redaction(s) "
                f"(Composite score: {context.composite_score:.2f})."
            )
            return PolicyDecision(
                request_id=context.request_id,
                action=PolicyAction.SANITIZE,
                is_approved=True,
                final_prompt=san_res.sanitized_prompt,
                applied_sanitizations=san_res.edits,
                reason=reason,
                metadata={
                    "rule": "SanitizationEligibilityRule",
                    "edit_count": len(san_res.edits),
                    "sanitization_time_ms": san_res.processing_time_ms,
                },
            )

        return None


class WarningMonitoringRule(BasePolicyRule):
    """
    Emits WARN decision for requests with elevated risk scores below the block/sanitize threshold.
    """

    def evaluate(
        self,
        context: RiskContext,
        config: PolicyEngineConfig,
        sanitization_pipeline: SanitizationPipeline,
    ) -> PolicyDecision | None:
        warn_threshold = config.thresholds.warn_score_threshold
        risk_lvl = str(context.risk_level).upper()

        if context.composite_score >= warn_threshold or risk_lvl in (
            "MEDIUM",
            "WARN",
            "MONITOR",
        ):
            reason = (
                f"Request approved with WARN monitoring directive (Composite score: {context.composite_score:.2f}, "
                f"Risk level: {context.risk_level})."
            )
            return PolicyDecision(
                request_id=context.request_id,
                action=PolicyAction.WARN,
                is_approved=True,
                final_prompt=context.original_prompt,
                reason=reason,
                metadata={"rule": "WarningMonitoringRule", "score": context.composite_score},
            )

        return None


class DefaultAllowRule(BasePolicyRule):
    """
    Default rule approving normal processing for low-risk requests.
    """

    def evaluate(
        self,
        context: RiskContext,
        config: PolicyEngineConfig,
        sanitization_pipeline: SanitizationPipeline,
    ) -> PolicyDecision:
        reason = (
            f"Request approved with ALLOW action (Composite score: {context.composite_score:.2f}, "
            f"Risk level: {context.risk_level})."
        )
        return PolicyDecision(
            request_id=context.request_id,
            action=PolicyAction.ALLOW,
            is_approved=True,
            final_prompt=context.original_prompt,
            reason=reason,
            metadata={"rule": "DefaultAllowRule", "score": context.composite_score},
        )
