"""
Immutable Domain Data Models for the Risk Engine — Sprint 7.

Defines canonical Data Transfer Objects (DTOs) exchanged between finding aggregation,
scoring calculators, confidence evaluators, policy mapper, and the Risk Engine facade.

Design Principles:
    - SOLID: Single responsibility per domain model.
    - DRY: Centralized protected validation routines for bounds and timestamps.
    - Immutability & Thread Safety: Enforced via `frozen=True` and `slots=True` with `Mapping` type hints.
    - OWASP Alignment: Preserves complete evidence provenance, auditability, and telemetry.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

from risk_engine.enums import RecommendedAction, RiskLevel
from risk_engine.exceptions import RiskValidationError


# ===========================================================================
# Internal Protected Validation Helpers (DRY)
# ===========================================================================


def _validate_normalized_score(value: float, name: str) -> None:
    """Validates that a numeric score lies strictly within the range [0.0, 1.0]."""
    if not (0.0 <= value <= 1.0):
        raise RiskValidationError(
            f"Validation error: '{name}' must be a normalized score between 0.0 and 1.0, got {value}"
        )


def _validate_confidence(value: float, name: str) -> None:
    """Validates that a confidence metric lies strictly within the range [0.0, 1.0]."""
    if not (0.0 <= value <= 1.0):
        raise RiskValidationError(
            f"Validation error: '{name}' must be a confidence value between 0.0 and 1.0, got {value}"
        )


def _validate_weight(value: float, name: str) -> None:
    """Validates that a feature weight lies strictly within the range [0.0, 1.0]."""
    if not (0.0 <= value <= 1.0):
        raise RiskValidationError(
            f"Validation error: '{name}' must be a weight between 0.0 and 1.0, got {value}"
        )


def _validate_non_negative(value: int | float, name: str) -> None:
    """Validates that a numeric parameter is non-negative."""
    if value < 0:
        raise RiskValidationError(
            f"Validation error: '{name}' must be non-negative, got {value}"
        )


def _validate_timestamp(timestamp: datetime, name: str) -> None:
    """Validates that a datetime instance is timezone-aware."""
    if not isinstance(timestamp, datetime):
        raise RiskValidationError(
            f"Validation error: '{name}' must be a valid datetime instance, got {type(timestamp)}"
        )
    if timestamp.tzinfo is None or timestamp.tzinfo.utcoffset(timestamp) is None:
        raise RiskValidationError(
            f"Validation error: '{name}' must be timezone-aware UTC datetime."
        )


# ===========================================================================
# Domain Data Models
# ===========================================================================


@dataclass(slots=True, frozen=True)
class RiskEvidence:
    """
    Represents an immutable, granular evidence item extracted from upstream security modules.

    Supports OWASP evidence preservation and complete audit trail traceability.

    Attributes:
        evidence_id: Unique UUID identifier for this evidence record.
        source_module: Upstream module name (e.g., 'PromptFirewall', 'InputValidator').
        detector_name: Specific detector or check name triggering the finding.
        finding_type: Standardized threat or validation finding type identifier.
        severity: Severity rating ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        confidence: Upstream detector confidence metric [0.0, 1.0].
        risk_score: Normalized risk score assigned to this individual finding [0.0, 1.0].
        description: Human-readable diagnostic description of the finding.
        metadata: Contextual dictionary mapping (matched text, character offsets, rule IDs).
        timestamp: Timezone-aware UTC timestamp of finding creation.
    """

    evidence_id: str
    source_module: str
    detector_name: str
    finding_type: str
    severity: str
    confidence: float
    risk_score: float
    description: str
    metadata: Mapping[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        """Validates evidence boundary limits and timestamp properties."""
        _validate_confidence(self.confidence, "confidence")
        _validate_normalized_score(self.risk_score, "risk_score")
        _validate_timestamp(self.timestamp, "timestamp")

    def to_dict(self) -> dict[str, Any]:
        """Serializes evidence entry to a dictionary for SIEM audit logging."""
        return {
            "evidence_id": self.evidence_id,
            "source_module": self.source_module,
            "detector_name": self.detector_name,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "description": self.description,
            "metadata": dict(self.metadata),
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass(slots=True, frozen=True)
class RiskScore:
    """
    Represents the output of a specific risk scoring strategy or component.

    Attributes:
        scoring_strategy: Identifier of the strategy ('weighted', 'threshold', 'adaptive', 'composite').
        raw_score: Non-normalized raw calculated component score (>= 0.0).
        normalized_score: Normalized component score strictly in range [0.0, 1.0].
        weight: Contribution weight assigned to this component [0.0, 1.0].
        confidence: Mathematical confidence associated with this score [0.0, 1.0].
        metadata: Diagnostic details regarding component calculation.
    """

    scoring_strategy: str
    raw_score: float
    normalized_score: float
    weight: float
    confidence: float
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validates score properties and normalized limits."""
        _validate_non_negative(self.raw_score, "raw_score")
        _validate_normalized_score(self.normalized_score, "normalized_score")
        _validate_weight(self.weight, "weight")
        _validate_confidence(self.confidence, "confidence")

    def to_dict(self) -> dict[str, Any]:
        """Serializes scoring component breakdown to a dictionary."""
        return {
            "scoring_strategy": self.scoring_strategy,
            "raw_score": self.raw_score,
            "normalized_score": self.normalized_score,
            "weight": self.weight,
            "confidence": self.confidence,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True, frozen=True)
class RiskAssessment:
    """
    Represents the aggregate risk assessment emitted by the Risk Engine.

    Acts as the single source of truth for downstream Policy Engine evaluation.

    Attributes:
        assessment_id: Unique UUID tracking this assessment instance.
        composite_score: Normalized aggregate risk score [0.0, 1.0].
        confidence_score: Overall mathematical confidence score [0.0, 1.0].
        risk_level: Assigned risk level ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        recommended_action: Recommended policy action ('ALLOW', 'MONITOR', 'BLOCK', etc.).
        evidence: Immutable tuple of contributing `RiskEvidence` items.
        scores: Immutable tuple of individual component `RiskScore` objects.
        metadata: Execution metadata, degradation flags, and request correlation IDs.
        timestamp: Timezone-aware UTC timestamp of assessment completion.
    """

    assessment_id: str
    composite_score: float
    confidence_score: float
    risk_level: RiskLevel | str
    recommended_action: RecommendedAction | str
    evidence: tuple[RiskEvidence, ...] = field(default_factory=tuple)
    scores: tuple[RiskScore, ...] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        """Validates aggregate scores, evidence containers, and timestamps."""
        _validate_normalized_score(self.composite_score, "composite_score")
        _validate_confidence(self.confidence_score, "confidence_score")
        _validate_timestamp(self.timestamp, "timestamp")

        # Convert mutable sequence to immutable tuple safely
        if not isinstance(self.evidence, tuple):
            object.__setattr__(self, "evidence", tuple(self.evidence))
        if not isinstance(self.scores, tuple):
            object.__setattr__(self, "scores", tuple(self.scores))

    def to_dict(self) -> dict[str, Any]:
        """Serializes complete assessment to a SIEM and OpenTelemetry audit dictionary."""
        return {
            "assessment_id": self.assessment_id,
            "composite_score": self.composite_score,
            "confidence_score": self.confidence_score,
            "risk_level": (
                self.risk_level.value
                if isinstance(self.risk_level, Enum)
                else self.risk_level
            ),
            "recommended_action": (
                self.recommended_action.value
                if isinstance(self.recommended_action, Enum)
                else self.recommended_action
            ),
            "evidence": [item.to_dict() for item in self.evidence],
            "scores": [score.to_dict() for score in self.scores],
            "metadata": dict(self.metadata),
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass(slots=True, frozen=True)
class RiskRecommendation:
    """
    Represents a non-binding downstream action recommendation emitted for the Policy Engine.

    Attributes:
        action: Recommended policy action ('ALLOW', 'MONITOR', 'BLOCK', etc.).
        reason: Human-readable explanation justifying the recommendation.
        priority: Priority level integer (>= 0).
        requires_human_review: Indicates if human-in-the-loop escalation is advised.
        metadata: Contextual policy override hints or trigger rule IDs.
    """

    action: RecommendedAction | str
    reason: str
    priority: int = 1
    requires_human_review: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validates priority bounds."""
        _validate_non_negative(self.priority, "priority")

    def to_dict(self) -> dict[str, Any]:
        """Serializes policy recommendation object to a dictionary."""
        return {
            "action": 
                self.action.value
                if isinstance(self.action, Enum)
                else self.action
            ,
            "reason": self.reason,
            "priority": self.priority,
            "requires_human_review": self.requires_human_review,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True, frozen=True)
class RiskTelemetry:
    """
    Represents diagnostic execution telemetry and pipeline performance metrics.

    Attributes:
        execution_time_ms: Total pipeline processing time in milliseconds (>= 0.0).
        scoring_strategy: Strategy name used for scoring calculation.
        aggregation_strategy: Strategy name used for finding aggregation.
        confidence_strategy: Strategy name used for confidence calculation.
        processed_evidence_count: Total count of processed upstream evidence items (>= 0).
        metadata: Additional diagnostic metrics (memory usage, thread ID).
    """

    execution_time_ms: float
    scoring_strategy: str
    aggregation_strategy: str
    confidence_strategy: str
    processed_evidence_count: int
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validates execution duration and item count non-negativity."""
        _validate_non_negative(self.execution_time_ms, "execution_time_ms")
        _validate_non_negative(
            self.processed_evidence_count, "processed_evidence_count"
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes telemetry data to a dictionary for monitoring exporters."""
        return {
            "execution_time_ms": self.execution_time_ms,
            "scoring_strategy": self.scoring_strategy,
            "aggregation_strategy": self.aggregation_strategy,
            "confidence_strategy": self.confidence_strategy,
            "processed_evidence_count": self.processed_evidence_count,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True, frozen=True)
class RiskEngineResponse:
    """
    Canonical response container returned by the public Risk Engine API facade.

    Attributes:
        assessment: Complete aggregated risk assessment DTO.
        recommendation: Downstream policy recommendation DTO.
        telemetry: Diagnostic execution telemetry DTO.
        timestamp: Timezone-aware UTC completion timestamp.
    """

    assessment: RiskAssessment
    recommendation: RiskRecommendation
    telemetry: RiskTelemetry
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        """Validates nested DTO types and completion timestamp."""
        _validate_timestamp(self.timestamp, "timestamp")
        if not isinstance(self.assessment, RiskAssessment):
            raise RiskValidationError(
                "Validation error: 'assessment' must be a valid RiskAssessment instance."
            )
        if not isinstance(self.recommendation, RiskRecommendation):
            raise RiskValidationError(
                "Validation error: 'recommendation' must be a valid RiskRecommendation instance."
            )
        if not isinstance(self.telemetry, RiskTelemetry):
            raise RiskValidationError(
                "Validation error: 'telemetry' must be a valid RiskTelemetry instance."
            )

    def to_dict(self) -> dict[str, Any]:
        """Serializes full Risk Engine response payload to a dictionary."""
        return {
            "assessment": self.assessment.to_dict(),
            "recommendation": self.recommendation.to_dict(),
            "telemetry": self.telemetry.to_dict(),
            "timestamp": self.timestamp.isoformat(),
        }
