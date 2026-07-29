r"""
Risk Engine Policy Mapping Module — Sprint 7.

Enterprise-grade policy mapping decision engine for the AI-SecOps Framework.

Purpose
-------
Provides the `PolicyMapper` component responsible for translating normalized
technical composite risk scores and confidence ratings into canonical security policy
recommendations (`RiskLevel`, `RecommendedAction`, `RiskRecommendation`).

`PolicyMapper` is a pure decision engine:
- It performs **no** risk score calculation.
- It performs **no** confidence evaluation.
- It performs **no** pipeline orchestration.

Responsibilities
----------------
1. Validate input score numeric ranges and boundary conditions [0.0, 1.0].
2. Evaluate configuration-driven policy threshold boundaries (`ThresholdConfig`).
3. Apply confidence-aware policy adjustment rules via dispatch table (e.g. low-confidence
   high-risk threats escalate to human review).
4. Assign deterministic `RiskLevel` classifications (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
5. Assign deterministic `RecommendedAction` policy directives (`ALLOW`,
   `ALLOW_WITH_MONITORING`, `ALLOW_WITH_WARNING`, `MONITOR`, `REVIEW`, `ESCALATE`, `BLOCK`).
6. Construct canonical, immutable `RiskRecommendation` DTOs.

Decision Flow
-------------
1. **Validation (`_validate_inputs` / `_validate_thresholds`)**: Verifies non-NaN,
   bounded scores, non-null evidence sequence, and valid threshold ordering ($low \le medium \le high \le critical$).
2. **Risk Level Classification (`_determine_risk_level`)**: Maps `composite_score` to
   `RiskLevel` using configuration thresholds.
3. **Action & Governance Dispatch (`_determine_action`)**: Dispatches `risk_level`
   to dedicated risk level mappers (`_map_low_risk`, `_map_medium_risk`, `_map_high_risk`,
   `_map_critical_risk`). High-confidence threats trigger immediate enforcement (`BLOCK`),
   while low-confidence threats escalate to human review (`ESCALATE` / `REVIEW`).
4. **Recommendation DTO Assembly (`_build_recommendation`)**: Constructs the final
   `RiskRecommendation` DTO with priority ratings and audit metadata.

Business Rules & Confidence Awareness
--------------------------------------
- **Determinism**: Identical inputs always produce identical policy outputs regardless
  of execution order or environment.
- **Fail-Secure & Confidence Scaling**:
  - `CRITICAL` risk + High confidence ($\ge 0.5$) $\rightarrow$ `BLOCK` (Immediate action).
  - `CRITICAL` risk + Low confidence ($< 0.5$) $\rightarrow$ `ESCALATE` (Urgent human review).
  - `HIGH` risk + High confidence ($\ge 0.5$) $\rightarrow$ `BLOCK`.
  - `HIGH` risk + Low confidence ($< 0.5$) $\rightarrow$ `REVIEW` (Human review mandatory).
  - `MEDIUM` risk + High confidence $\rightarrow$ `ALLOW_WITH_MONITORING`.
  - `MEDIUM` risk + Low confidence $\rightarrow$ `ALLOW_WITH_WARNING`.
  - `LOW` risk + High confidence $\rightarrow$ `ALLOW`.
  - `LOW` risk + Low confidence $\rightarrow$ `ALLOW_WITH_MONITORING`.
- Low confidence **never** silently weakens a security decision.

Complexity
----------
- **Time Complexity**: O(1) constant time validation and policy mapping.
- **Memory Complexity**: O(1) auxiliary space.

Thread Safety
-------------
`PolicyMapper` is completely stateless and thread-safe. It retains no request-specific
mutable state between calls. Incoming evidence is never mutated.

Security Considerations
-----------------------
- OWASP Top 10 for LLM Applications alignment: Enforces deterministic AI safety policies
  and complete explainability for security governance.
- Fail-Secure: Input validation and strict mode options prevent bypass from malformed scores.

Future Extensibility
--------------------
Designed with open-closed principles to support dynamic custom policy rules, role-based
overrides, or tenant-specific policy matrix configurations without breaking public APIs.
"""

from __future__ import annotations

import math
from collections.abc import Sequence

from risk_engine.config import RiskEngineConfig
from risk_engine.constants import RISK_LEVEL_PRIORITY
from risk_engine.enums import RecommendedAction, RiskLevel
from risk_engine.exceptions import (
    InvalidRiskInputError,
    RiskEngineConfigurationError,
    RiskEngineError,
    RiskEngineExecutionError,
)
from risk_engine.models import RiskEvidence, RiskRecommendation
from risk_engine.utils import validate_numeric_score


__all__ = ["PolicyMapper"]


class PolicyMapper:
    """
    Stateless, enterprise-grade Policy Mapper decision engine.

    Translates technical composite risk scores and confidence ratings into
    type-safe RiskLevel, RecommendedAction, and RiskRecommendation DTOs.
    """

    def __init__(self, config: RiskEngineConfig | None = None) -> None:
        """
        Initialize PolicyMapper with optional configuration.

        Args:
            config: Risk Engine configuration instance. Uses default if None.

        Raises:
            RiskEngineConfigurationError: If threshold configuration is invalid.
        """
        self._config: RiskEngineConfig = config or RiskEngineConfig()
        self._validate_thresholds()

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def map_policy(
        self,
        composite_score: float,
        confidence_score: float,
        evidence: Sequence[RiskEvidence],
    ) -> tuple[RiskLevel, RecommendedAction, RiskRecommendation]:
        """
        Map composite risk score and confidence rating to security policy decisions.

        Args:
            composite_score: Normalized composite risk score in [0.0, 1.0].
            confidence_score: Normalized confidence rating in [0.0, 1.0].
            evidence: Sequence of contributing RiskEvidence items.

        Returns:
            tuple[RiskLevel, RecommendedAction, RiskRecommendation]: Assigned RiskLevel,
            RecommendedAction, and RiskRecommendation DTO.

        Raises:
            InvalidRiskInputError: If scores are non-numeric or out of bounds [0.0, 1.0].
            RiskEngineExecutionError: If an error occurs during policy mapping.
        """
        self._validate_inputs(composite_score, confidence_score, evidence)

        try:
            # Step 1: Determine RiskLevel tier from composite score
            risk_level = self._determine_risk_level(composite_score)

            # Step 2: Determine RecommendedAction and human review flag based on risk & confidence
            action, requires_review, reason = self._determine_action(
                risk_level, composite_score, confidence_score
            )

            # Step 3: Construct RiskRecommendation DTO
            recommendation = self._build_recommendation(
                action=action,
                risk_level=risk_level,
                composite_score=composite_score,
                confidence_score=confidence_score,
                reason=reason,
                requires_human_review=requires_review,
                evidence=evidence,
            )

            return risk_level, action, recommendation

        except (InvalidRiskInputError, RiskEngineConfigurationError):
            raise
        except Exception as exc:
            raise RiskEngineExecutionError(
                message=f"Failed to map risk score to policy recommendation: {exc}",
                details={
                    "composite_score": composite_score,
                    "confidence_score": confidence_score,
                },
                cause=exc,
            ) from exc

    # =========================================================================
    # PROTECTED HELPER METHODS
    # =========================================================================

    def _validate_inputs(
        self,
        composite_score: float,
        confidence_score: float,
        evidence: Sequence[RiskEvidence],
    ) -> None:
        """
        Validate input scores and evidence for numeric bounds and type integrity.

        Args:
            composite_score: Normalized score to validate.
            confidence_score: Confidence rating to validate.
            evidence: Sequence of evidence items.

        Raises:
            InvalidRiskInputError: If scores are NaN, Infinite, or evidence is not a valid Sequence.
        """
        validate_numeric_score(composite_score, field_name="composite_score")
        validate_numeric_score(confidence_score, field_name="confidence_score")

        if evidence is None or not isinstance(evidence, Sequence):
            raise InvalidRiskInputError(
                message=f"evidence must be a valid Sequence instance, got {type(evidence).__name__ if evidence is not None else 'None'}.",
                details={"field": "evidence", "value": evidence},
            )


    def _validate_thresholds(self) -> None:
        """
        Validate that threshold boundaries in configuration are correctly ordered.

        Raises:
            RiskEngineConfigurationError: If thresholds are invalid.
        """
        t = self._config.thresholds
        if not (t.low <= t.medium <= t.high <= t.critical):
            raise RiskEngineConfigurationError(
                message=f"Configured thresholds are invalidly ordered: low={t.low}, medium={t.medium}, high={t.high}, critical={t.critical}.",
                details={"field": "thresholds", "value": {"low": t.low, "medium": t.medium, "high": t.high, "critical": t.critical}},
            )

    def _determine_risk_level(self, composite_score: float) -> RiskLevel:
        """
        Determine RiskLevel classification based on configuration thresholds.

        Args:
            composite_score: Normalized risk score.

        Returns:
            RiskLevel: Classified risk level enum.
        """
        t = self._config.thresholds
        if composite_score < t.low:
            return RiskLevel.LOW
        if composite_score < t.medium:
            return RiskLevel.MEDIUM
        if composite_score < t.high:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL

    def _determine_action(
        self,
        risk_level: RiskLevel,
        composite_score: float,
        confidence_score: float,
    ) -> tuple[RecommendedAction, bool, str]:
        """
        Determine RecommendedAction and human review flag using a dispatch table.

        Fail-Secure & Confidence Aware: Low confidence escalates decision scrutiny.

        Args:
            risk_level: Classified RiskLevel.
            composite_score: Normalized risk score.
            confidence_score: Normalized confidence rating.

        Returns:
            tuple[RecommendedAction, bool, str]: RecommendedAction enum, requires_human_review bool, and reason string.
        """
        conf_threshold = self._config.confidence.default_confidence
        is_low_confidence = confidence_score < conf_threshold

        dispatch = {
            RiskLevel.LOW: self._map_low_risk,
            RiskLevel.MEDIUM: self._map_medium_risk,
            RiskLevel.HIGH: self._map_high_risk,
            RiskLevel.CRITICAL: self._map_critical_risk,
        }

        handler = dispatch.get(risk_level, self._map_critical_risk)
        return handler(composite_score, confidence_score, is_low_confidence)

    def _map_low_risk(
        self,
        composite_score: float,
        confidence_score: float,
        is_low_confidence: bool,
    ) -> tuple[RecommendedAction, bool, str]:
        """Map LOW risk level to action and reason."""
        if is_low_confidence:
            return (
                RecommendedAction.ALLOW_WITH_MONITORING,
                False,
                f"LOW risk level detected (score={composite_score:.4f}) with uncalibrated confidence ({confidence_score:.4f}). Allowed with active monitoring.",
            )
        return (
            RecommendedAction.ALLOW,
            False,
            f"LOW risk level verified (score={composite_score:.4f}) with high confidence ({confidence_score:.4f}). Request allowed.",
        )

    def _map_medium_risk(
        self,
        composite_score: float,
        confidence_score: float,
        is_low_confidence: bool,
    ) -> tuple[RecommendedAction, bool, str]:
        """Map MEDIUM risk level to action and reason."""
        if is_low_confidence:
            return (
                RecommendedAction.ALLOW_WITH_WARNING,
                True,
                f"MEDIUM risk level detected (score={composite_score:.4f}) with low confidence ({confidence_score:.4f}). Warning issued and flagged for secondary review.",
            )
        return (
            RecommendedAction.ALLOW_WITH_MONITORING,
            False,
            f"MEDIUM risk level confirmed (score={composite_score:.4f}) with high confidence ({confidence_score:.4f}). Allowed with session monitoring.",
        )

    def _map_high_risk(
        self,
        composite_score: float,
        confidence_score: float,
        is_low_confidence: bool,
    ) -> tuple[RecommendedAction, bool, str]:
        """Map HIGH risk level to action and reason."""
        if is_low_confidence:
            return (
                RecommendedAction.REVIEW,
                True,
                f"HIGH risk level detected (score={composite_score:.4f}) with low confidence ({confidence_score:.4f}). Flagged for human review.",
            )
        return (
            RecommendedAction.BLOCK,
            False,
            f"HIGH risk level confirmed (score={composite_score:.4f}) with high confidence ({confidence_score:.4f}). Block recommended.",
        )

    def _map_critical_risk(
        self,
        composite_score: float,
        confidence_score: float,
        is_low_confidence: bool,
    ) -> tuple[RecommendedAction, bool, str]:
        """Map CRITICAL risk level to action and reason."""
        if is_low_confidence:
            return (
                RecommendedAction.ESCALATE,
                True,
                f"CRITICAL risk level detected (score={composite_score:.4f}) with low confidence ({confidence_score:.4f}). Escalated for urgent human review.",
            )
        return (
            RecommendedAction.BLOCK,
            False,
            f"CRITICAL risk level confirmed (score={composite_score:.4f}) with high confidence ({confidence_score:.4f}). Immediate block enforced.",
        )

    def _build_recommendation(
        self,
        action: RecommendedAction,
        risk_level: RiskLevel,
        composite_score: float,
        confidence_score: float,
        reason: str,
        requires_human_review: bool,
        evidence: Sequence[RiskEvidence],
    ) -> RiskRecommendation:
        """
        Assemble the canonical RiskRecommendation DTO.

        Args:
            action: Assigned RecommendedAction.
            risk_level: Classified RiskLevel.
            composite_score: Raw score.
            confidence_score: Raw confidence.
            reason: Explanatory text.
            requires_human_review: Flag.
            evidence: Evidence collection.

        Returns:
            RiskRecommendation: Immutable recommendation DTO.
        """
        priority = RISK_LEVEL_PRIORITY.get(risk_level, 1)

        meta = {
            "risk_level": risk_level.value,
            "composite_score": composite_score,
            "confidence_score": confidence_score,
            "evidence_count": len(evidence),
            "strict_mode": self._config.policy_mapping.strict_mode,
        }

        return RiskRecommendation(
            action=action,
            reason=reason,
            priority=priority,
            requires_human_review=requires_human_review,
            metadata=meta,
        )
