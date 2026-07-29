"""
Risk Engine Orchestration Module — Sprint 7.

Centralized pipeline orchestrator and facade service for the AI-SecOps Risk Engine.

Purpose
-------
Provides the `RiskEngine` orchestration service responsible for coordinating all
submodules of the Risk Engine framework: `RiskAggregator`, `CompositeScorer`,
`ConfidenceCalculator`, and `PolicyMapper`.

`RiskEngine` is a thin orchestration service: it executes no direct business logic,
scoring calculations, or policy evaluations internally. It delegates each stage to
injected domain components while recording lifecycle telemetry via `RiskTelemetry`,
enforcing fail-secure error handling, and maintaining thread safety.

Responsibilities
----------------
1. Orchestrate the complete end-to-end Risk Engine processing pipeline:
   Inputs -> RiskAggregator -> CompositeScorer -> ConfidenceCalculator -> PolicyMapper -> RiskAssessment.
2. Validate incoming security finding payloads.
3. Record high-resolution execution timing telemetry via `RiskTelemetry`.
4. Support dependency injection for all pipeline stage handlers.
5. Guarantee fail-secure exception handling by wrapping unexpected faults in
   `RiskEngineExecutionError`.
6. Return canonical `RiskAssessment` (and `RiskEngineResponse`) domain DTOs.

Pipeline
--------
1. **Input Validation (`_validate_inputs`)**: Verifies finding payload presence.
2. **Evidence Aggregation (`_aggregate_evidence`)**: Consolidates multi-source findings
   into a normalized, deduplicated `RiskEvidence` collection using `RiskAggregator`.
3. **Composite Risk Scoring (`_calculate_risk_score`)**: Computes a normalized
   composite risk score using `CompositeScorer`.
4. **Confidence Evaluation (`_calculate_confidence`)**: Evaluates mathematical
   certainty and consensus using `ConfidenceCalculator`.
5. **Policy Mapping (`_map_policy`)**: Maps risk and confidence ratings to non-binding
   policy recommendations using `PolicyMapper`.
6. **Assessment Construction (`_build_assessment`)**: Assembles the immutable
   `RiskAssessment` DTO enriched with `RiskTelemetry`.

Complexity
----------
- **Time Complexity**: O(N log N) dominated by evidence aggregation and sorting,
  where N is the number of input evidence items.
- **Memory Complexity**: O(N) linear space for evidence collections.

Thread Safety
-------------
`RiskEngine` is completely stateless and thread-safe. It retains no request-specific
mutable state between calls. Injected dependencies are treated as immutable.

Security Considerations
-----------------------
- OWASP Top 10 for LLM Applications alignment: Ensures complete auditability,
  evidence provenance, and strict fail-secure execution bounds.
- Fail-Secure: Unexpected errors wrap into `RiskEngineExecutionError` to guarantee
  the pipeline fails to a safe state without exposing internal diagnostics.

Future Extensibility
--------------------
Designed with open-closed principles to easily insert future pipeline stages
(e.g., Output Guard, Threat Intelligence feeds, RAG Scanners, Guardrails,
Explainability Engines) without altering the core orchestration contract.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Sequence
from datetime import datetime, timezone

from risk_engine.aggregation import RiskAggregator
from risk_engine.base_scorer import BaseScorer
from risk_engine.config import RiskEngineConfig
from risk_engine.confidence import ConfidenceCalculator
from risk_engine.enums import RecommendedAction, RiskLevel
from risk_engine.exceptions import (
    InvalidRiskInputError,
    RiskEngineConfigurationError,
    RiskEngineError,
    RiskEngineExecutionError,
)
from risk_engine.models import (
    RiskAssessment,
    RiskEngineResponse,
    RiskEvidence,
    RiskRecommendation,
    RiskScore,
    RiskTelemetry,
)
from risk_engine.policy_mapper import PolicyMapper
from risk_engine.scoring.composite import CompositeScorer

__all__ = ["RiskEngine"]


class RiskEngine:
    """
    Stateless, enterprise-grade Risk Engine orchestrator and facade service.

    Coordinates upstream findings through RiskAggregator, CompositeScorer,
    ConfidenceCalculator, and PolicyMapper to produce RiskAssessment results.
    """

    def __init__(
        self,
        config: RiskEngineConfig | None = None,
        aggregator: RiskAggregator | None = None,
        scorer: CompositeScorer | BaseScorer | None = None,
        confidence_calculator: ConfidenceCalculator | None = None,
        policy_mapper: PolicyMapper | None = None,
    ) -> None:
        """
        Initialize the RiskEngine orchestrator with injected dependencies.

        Args:
            config: Risk Engine configuration instance.
            aggregator: Injected RiskAggregator instance.
            scorer: Injected CompositeScorer or BaseScorer instance.
            confidence_calculator: Injected ConfidenceCalculator instance.
            policy_mapper: Injected PolicyMapper instance.

        Raises:
            RiskEngineConfigurationError: If mandatory dependencies are missing.
        """
        self._config: RiskEngineConfig = config or RiskEngineConfig()
        self._aggregator: RiskAggregator = aggregator or RiskAggregator(self._config)
        self._scorer: CompositeScorer | BaseScorer | None = scorer
        self._confidence_calculator: ConfidenceCalculator = (
            confidence_calculator or ConfidenceCalculator(self._config)
        )
        self._policy_mapper: PolicyMapper | None = policy_mapper

        self._validate_configuration()

    def _validate_configuration(self) -> None:
        """
        Validate that mandatory orchestration dependencies are injected.

        Raises:
            RiskEngineConfigurationError: If scorer or policy_mapper is missing.
        """
        if self._scorer is None:
            raise RiskEngineConfigurationError(
                message="CompositeScorer dependency is required and must be injected into RiskEngine.",
                field="scorer",
                value=None,
            )
        if self._policy_mapper is None:
            raise RiskEngineConfigurationError(
                message="PolicyMapper dependency is required and must be injected into RiskEngine.",
                field="policy_mapper",
                value=None,
            )

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def evaluate(
        self,
        *sources: RiskEvidence | Sequence[RiskEvidence] | object,
        merge_strategy: str | None = None,
        confidence_strategy: str | None = None,
    ) -> RiskAssessment:
        """
        Evaluate security findings through the complete Risk Engine orchestration pipeline.

        Args:
            *sources: Heterogeneous finding inputs (RiskEvidence, ValidationResult,
                DetectionResult, InputValidationResponse, FirewallResponse, lists, dicts).
            merge_strategy: Optional override for duplicate merge strategy.
            confidence_strategy: Optional override for confidence calculation strategy.

        Returns:
            RiskAssessment: Immutable assessment DTO containing composite score,
            confidence rating, assigned risk level, recommended action, evidence, and telemetry.

        Raises:
            InvalidRiskInputError: If sources are empty or unparseable.
            RiskEngineConfigurationError: If orchestrator dependencies are unconfigured.
            RiskEngineExecutionError: If an unhandled error occurs during pipeline execution.
        """
        start_total = time.perf_counter()

        try:
            # Step 1: Input Validation
            self._validate_inputs(*sources)

            # Step 2: Evidence Aggregation
            t0 = time.perf_counter()
            evidence = self._aggregator.aggregate(*sources, merge_strategy=merge_strategy)
            aggregation_time_ms = (time.perf_counter() - t0) * 1000.0

            # Step 3: Composite Risk Scoring
            t0 = time.perf_counter()
            risk_score_obj = self._calculate_risk_score(evidence)
            scoring_time_ms = (time.perf_counter() - t0) * 1000.0

            # Step 4: Confidence Evaluation
            t0 = time.perf_counter()
            confidence_score = self._confidence_calculator.calculate(
                evidence, strategy=confidence_strategy
            )
            confidence_time_ms = (time.perf_counter() - t0) * 1000.0

            # Step 5: Policy Mapping
            t0 = time.perf_counter()
            risk_level, recommended_action, recommendation = self._map_policy(
                risk_score_obj.normalized_score, confidence_score, evidence
            )
            policy_mapping_time_ms = (time.perf_counter() - t0) * 1000.0

            total_execution_time_ms = (time.perf_counter() - start_total) * 1000.0

            # Step 6: Construct RiskTelemetry & RiskAssessment
            telemetry = RiskTelemetry(
                execution_time_ms=total_execution_time_ms,
                scoring_strategy=getattr(risk_score_obj, "scoring_strategy", "COMPOSITE"),
                aggregation_strategy=self._config.aggregation.strategy,
                confidence_strategy=str(confidence_strategy or "WEIGHTED"),
                processed_evidence_count=len(evidence),
                metadata={
                    "aggregation_time_ms": round(aggregation_time_ms, 2),
                    "scoring_time_ms": round(scoring_time_ms, 2),
                    "confidence_time_ms": round(confidence_time_ms, 2),
                    "policy_mapping_time_ms": round(policy_mapping_time_ms, 2),
                    "total_execution_time_ms": round(total_execution_time_ms, 2),
                },
            )

            return self._build_assessment(
                evidence=evidence,
                risk_score_obj=risk_score_obj,
                confidence_score=confidence_score,
                risk_level=risk_level,
                recommended_action=recommended_action,
                recommendation=recommendation,
                telemetry=telemetry,
            )

        except (InvalidRiskInputError, RiskEngineError):
            raise
        except Exception as exc:
            raise RiskEngineExecutionError.wrap(
                cause=exc,
                message=f"RiskEngine pipeline execution failed securely: {exc}",
                details={"stage": "orchestration"},
            ) from exc

    def evaluate_response(
        self,
        *sources: RiskEvidence | Sequence[RiskEvidence] | object,
        merge_strategy: str | None = None,
        confidence_strategy: str | None = None,
    ) -> RiskEngineResponse:
        """
        Evaluate security findings and return full RiskEngineResponse payload.

        Args:
            *sources: Heterogeneous finding inputs.
            merge_strategy: Optional override for duplicate merge strategy.
            confidence_strategy: Optional override for confidence calculation strategy.

        Returns:
            RiskEngineResponse: Canonical gateway response container.
        """
        assessment = self.evaluate(
            *sources,
            merge_strategy=merge_strategy,
            confidence_strategy=confidence_strategy,
        )

        telemetry_dict = assessment.metadata.get("telemetry", {})
        telemetry = RiskTelemetry(
            execution_time_ms=float(telemetry_dict.get("execution_time_ms", 0.0)),
            scoring_strategy=str(telemetry_dict.get("scoring_strategy", "COMPOSITE")),
            aggregation_strategy=str(telemetry_dict.get("aggregation_strategy", self._config.aggregation.strategy)),
            confidence_strategy=str(telemetry_dict.get("confidence_strategy", "WEIGHTED")),
            processed_evidence_count=len(assessment.evidence),
            metadata=dict(telemetry_dict.get("metadata", {})),
        )

        # Extract recommendation object from assessment metadata without duplication
        rec_dict = assessment.metadata.get("recommendation", {})
        recommendation = RiskRecommendation(
            action=assessment.recommended_action,
            reason=rec_dict.get("reason", f"Policy recommendation for {assessment.risk_level}."),
            priority=rec_dict.get("priority", 1),
            requires_human_review=rec_dict.get("requires_human_review", False),
            metadata=dict(rec_dict.get("metadata", {})),
        )

        return RiskEngineResponse(
            assessment=assessment,
            recommendation=recommendation,
            telemetry=telemetry,
            timestamp=datetime.now(timezone.utc),
        )

    # =========================================================================
    # PROTECTED LIFE-CYCLE HELPER METHODS
    # =========================================================================

    def _validate_inputs(
        self, *sources: RiskEvidence | Sequence[RiskEvidence] | object
    ) -> None:
        """
        Validate presence of input finding payloads.

        Args:
            *sources: Input finding arguments.

        Raises:
            InvalidRiskInputError: If sources are empty.
        """
        if not sources:
            raise InvalidRiskInputError(
                message="Input sources cannot be empty for RiskEngine evaluation.",
                field="sources",
                value=sources,
            )

    def _calculate_risk_score(self, evidence: list[RiskEvidence]) -> RiskScore:
        """
        Delegate composite risk score calculation to injected scorer.

        Args:
            evidence: List of RiskEvidence objects.

        Returns:
            RiskScore: Computed RiskScore domain DTO.

        Raises:
            RiskEngineConfigurationError: If scorer is unavailable.
        """
        if self._scorer is None:
            raise RiskEngineConfigurationError(
                message="CompositeScorer dependency is unconfigured.",
                field="scorer",
                value=None,
            )
        return self._scorer.score(evidence)

    def _map_policy(
        self,
        composite_score: float,
        confidence_score: float,
        evidence: list[RiskEvidence],
    ) -> tuple[RiskLevel, RecommendedAction, RiskRecommendation]:
        """
        Delegate policy decision mapping to injected PolicyMapper.

        Args:
            composite_score: Normalized aggregate risk score [0.0, 1.0].
            confidence_score: Normalized confidence rating [0.0, 1.0].
            evidence: Collection of RiskEvidence objects.

        Returns:
            tuple[RiskLevel, RecommendedAction, RiskRecommendation]: Assigned risk level,
            recommended action, and detailed RiskRecommendation DTO.

        Raises:
            RiskEngineConfigurationError: If PolicyMapper is unavailable.
        """
        if self._policy_mapper is None:
            raise RiskEngineConfigurationError(
                message="PolicyMapper dependency is unconfigured.",
                field="policy_mapper",
                value=None,
            )

        return self._policy_mapper.map_policy(
            composite_score, confidence_score, evidence
        )

    def _build_assessment(
        self,
        evidence: list[RiskEvidence],
        risk_score_obj: RiskScore,
        confidence_score: float,
        risk_level: RiskLevel,
        recommended_action: RecommendedAction,
        recommendation: RiskRecommendation,
        telemetry: RiskTelemetry,
    ) -> RiskAssessment:
        """
        Assemble the canonical RiskAssessment DTO enriched with RiskTelemetry.

        Args:
            evidence: List of processed RiskEvidence items.
            risk_score_obj: Computed RiskScore DTO.
            confidence_score: Computed confidence rating.
            risk_level: Assigned RiskLevel enum.
            recommended_action: Assigned RecommendedAction enum.
            recommendation: Policy recommendation DTO from PolicyMapper.
            telemetry: Execution RiskTelemetry model.

        Returns:
            RiskAssessment: Fully populated immutable domain assessment DTO.
        """
        metadata = {
            "telemetry": telemetry.to_dict(),
            "recommendation": recommendation.to_dict(),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

        return RiskAssessment(
            assessment_id=str(uuid.uuid4()),
            composite_score=risk_score_obj.normalized_score,
            confidence_score=confidence_score,
            risk_level=risk_level,
            recommended_action=recommended_action,
            evidence=tuple(evidence),
            scores=(risk_score_obj,),
            metadata=metadata,
            timestamp=datetime.now(timezone.utc),
        )
