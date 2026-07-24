"""
risk_engine/config.py
=====================

Centralized configuration for the AI-SecOps Risk Engine.

Provides immutable, validated configuration dataclasses for all scoring
strategies, thresholds, confidence calculations, aggregation policies,
and adaptive adjustments.

Thread Safety
-------------
All configuration classes use ``frozen=True`` and ``slots=True``, ensuring
immutability and thread safety. Instances can be shared safely across
concurrent scoring operations.

Security & Governance
---------------------
- Input validation prevents misconfiguration that could lead to score
  manipulation or bypass.
- Factor bounds enforce explainable, bounded adjustments.
- Configuration errors are explicit and auditable.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .exceptions import RiskEngineConfigurationError


__all__ = [
    "AdaptiveConfig",
    "AggregationConfig",
    "ConfidenceConfig",
    "PolicyMappingConfig",
    "RiskEngineConfig",
    "ScoringConfig",
    "ThresholdConfig",
]


# ====================================================================== #
# HELPER FUNCTIONS
# ====================================================================== #

def _validate_positive(value: float, field_name: str) -> None:
    """
    Validate that a numeric value is strictly positive.

    Args:
        value: The value to validate.
        field_name: Fully qualified field name for error attribution.

    Raises:
        RiskEngineConfigurationError: If value is not positive.
    """
    if value <= 0:
        raise RiskEngineConfigurationError(
            message=f"{field_name} must be positive, got {value}.",
            field=field_name,
            value=value,
        )


def _validate_non_negative(value: float, field_name: str) -> None:
    """
    Validate that a numeric value is non-negative.

    Args:
        value: The value to validate.
        field_name: Fully qualified field name for error attribution.

    Raises:
        RiskEngineConfigurationError: If value is negative.
    """
    if value < 0:
        raise RiskEngineConfigurationError(
            message=f"{field_name} must be non-negative, got {value}.",
            field=field_name,
            value=value,
        )


def _validate_range(
    value: float,
    field_name: str,
    min_val: float,
    max_val: float,
) -> None:
    """
    Validate that a numeric value is within an inclusive range.

    Args:
        value: The value to validate.
        field_name: Fully qualified field name for error attribution.
        min_val: Minimum allowed value.
        max_val: Maximum allowed value.

    Raises:
        RiskEngineConfigurationError: If value is outside the range.
    """
    if not (min_val <= value <= max_val):
        raise RiskEngineConfigurationError(
            message=(
                f"{field_name} must be between {min_val} and {max_val}, "
                f"got {value}."
            ),
            field=field_name,
            value=value,
        )


def _validate_factor_bounds(
    factors: Mapping[str, float],
    field_prefix: str,
) -> None:
    """
    Validate that every factor in the mapping is within secure bounds.

    Args:
        factors: Mapping of factor names to factor values.
        field_prefix: Prefix for error field attribution.

    Raises:
        RiskEngineConfigurationError: If any factor is outside ``[0.0, 2.0]``
            or is non-numeric.
    """
    for name, value in factors.items():
        if not isinstance(value, (int, float)):
            raise RiskEngineConfigurationError(
                message=(
                    f"Factor '{name}' in {field_prefix} must be numeric, "
                    f"got {type(value).__name__}."
                ),
                field=f"{field_prefix}[{name}]",
                value=value,
            )
        if not (0.0 <= float(value) <= 2.0):
            raise RiskEngineConfigurationError(
                message=(
                    f"Factor '{name}' in {field_prefix} must be between "
                    f"0.0 and 2.0, got {value}."
                ),
                field=f"{field_prefix}[{name}]",
                value=value,
            )


# ====================================================================== #
# SCORING CONFIGURATION
# ====================================================================== #

@dataclass(slots=True, frozen=True)
class ScoringConfig:
    """
    Configuration for general scoring behavior.
    """

    precision: int = 4
    min_score: float = 0.0
    max_score: float = 1.0
    require_normalized_weights: bool = True
    weight_tolerance: float = 1e-6

    def __post_init__(self) -> None:
        _validate_positive(self.precision, "scoring.precision")
        _validate_range(self.min_score, "scoring.min_score", 0.0, 1.0)
        _validate_range(self.max_score, "scoring.max_score", 0.0, 1.0)
        if self.min_score > self.max_score:
            raise RiskEngineConfigurationError(
                message=(
                    f"scoring.min_score ({self.min_score}) cannot exceed "
                    f"scoring.max_score ({self.max_score})."
                ),
                field="scoring.min_score",
                value=self.min_score,
            )
        _validate_positive(self.weight_tolerance, "scoring.weight_tolerance")


# ====================================================================== #
# THRESHOLD CONFIGURATION
# ====================================================================== #

@dataclass(slots=True, frozen=True)
class ThresholdConfig:
    """
    Configuration for threshold-based scoring and policy mapping triggers.
    """

    critical: float = 0.9
    high: float = 0.7
    medium: float = 0.4
    low: float = 0.1

    def __post_init__(self) -> None:
        _validate_range(self.critical, "thresholds.critical", 0.0, 1.0)
        _validate_range(self.high, "thresholds.high", 0.0, 1.0)
        _validate_range(self.medium, "thresholds.medium", 0.0, 1.0)
        _validate_range(self.low, "thresholds.low", 0.0, 1.0)

        if not (self.low <= self.medium <= self.high <= self.critical):
            raise RiskEngineConfigurationError(
                message=(
                    "Thresholds must be ordered: low <= medium <= high <= critical. "
                    f"Got: low={self.low}, medium={self.medium}, "
                    f"high={self.high}, critical={self.critical}."
                ),
                field="thresholds",
                value={
                    "low": self.low,
                    "medium": self.medium,
                    "high": self.high,
                    "critical": self.critical,
                },
            )


# ====================================================================== #
# CONFIDENCE CONFIGURATION
# ====================================================================== #

@dataclass(slots=True, frozen=True)
class ConfidenceConfig:
    """
    Configuration for confidence score calculations.
    """

    default_confidence: float = 0.5
    min_confidence: float = 0.0
    max_confidence: float = 1.0

    def __post_init__(self) -> None:
        _validate_range(
            self.default_confidence,
            "confidence.default_confidence",
            0.0,
            1.0,
        )
        _validate_range(self.min_confidence, "confidence.min_confidence", 0.0, 1.0)
        _validate_range(self.max_confidence, "confidence.max_confidence", 0.0, 1.0)
        if self.min_confidence > self.max_confidence:
            raise RiskEngineConfigurationError(
                message=(
                    f"confidence.min_confidence ({self.min_confidence}) cannot exceed "
                    f"confidence.max_confidence ({self.max_confidence})."
                ),
                field="confidence.min_confidence",
                value=self.min_confidence,
            )


# ====================================================================== #
# AGGREGATION CONFIGURATION
# ====================================================================== #

@dataclass(slots=True, frozen=True)
class AggregationConfig:
    """
    Configuration for multi-source score aggregation strategies.
    """

    strategy: str = "mean"
    min_sources: int = 1
    outlier_threshold: float = 2.0

    def __post_init__(self) -> None:
        valid_strategies = {"mean", "median", "max", "min", "weighted"}
        if self.strategy not in valid_strategies:
            raise RiskEngineConfigurationError(
                message=(
                    f"aggregation.strategy must be one of {valid_strategies}, "
                    f"got '{self.strategy}'."
                ),
                field="aggregation.strategy",
                value=self.strategy,
            )
        _validate_positive(self.min_sources, "aggregation.min_sources")
        _validate_positive(self.outlier_threshold, "aggregation.outlier_threshold")


# ====================================================================== #
# POLICY MAPPING CONFIGURATION
# ====================================================================== #

@dataclass(slots=True, frozen=True)
class PolicyMappingConfig:
    """
    Configuration for risk-score-to-policy mapping.
    """

    enabled: bool = True
    default_policy: str = "review"
    strict_mode: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise RiskEngineConfigurationError(
                message=f"policy_mapping.enabled must be bool, got {type(self.enabled).__name__}.",
                field="policy_mapping.enabled",
                value=self.enabled,
            )
        if not isinstance(self.strict_mode, bool):
            raise RiskEngineConfigurationError(
                message=f"policy_mapping.strict_mode must be bool, got {type(self.strict_mode).__name__}.",
                field="policy_mapping.strict_mode",
                value=self.strict_mode,
            )


# ====================================================================== #
# ADAPTIVE CONFIGURATION
# ====================================================================== #

@dataclass(slots=True, frozen=True)
class AdaptiveConfig:
    """
    Configuration for adaptive risk scoring strategies.

    Provides detector-specific and finding-type-specific adjustment factors
    to dynamically modulate risk scores based on contextual evidence.

    Thread Safety
    -------------
    ``frozen=True`` ensures immutability. Safe for concurrent access.

    Security
    --------
    Factor bounds (0.0–2.0) prevent extreme score inflation or deflation,
    supporting AI governance and explainability requirements.
    """

    detector_factors: Mapping[str, float] = field(default_factory=dict)
    finding_type_factors: Mapping[str, float] = field(default_factory=dict)
    default_factor: float = 1.0
    enable_detector_adjustment: bool = True
    enable_finding_type_adjustment: bool = True

    def __post_init__(self) -> None:
        _validate_positive(self.default_factor, "adaptive.default_factor")
        _validate_factor_bounds(
            factors=self.detector_factors,
            field_prefix="adaptive.detector_factors",
        )
        _validate_factor_bounds(
            factors=self.finding_type_factors,
            field_prefix="adaptive.finding_type_factors",
        )


# ====================================================================== #
# RISK ENGINE CONFIGURATION (ROOT)
# ====================================================================== #

@dataclass(slots=True, frozen=True)
class RiskEngineConfig:
    """
    Root configuration container for the Risk Engine.

    Aggregates all sub-configurations and provides centralized validation.
    """

    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)
    confidence: ConfidenceConfig = field(default_factory=ConfidenceConfig)
    aggregation: AggregationConfig = field(default_factory=AggregationConfig)
    policy_mapping: PolicyMappingConfig = field(default_factory=PolicyMappingConfig)
    adaptive: AdaptiveConfig = field(default_factory=AdaptiveConfig)

    def __post_init__(self) -> None:
        if not isinstance(self.scoring, ScoringConfig):
            raise RiskEngineConfigurationError(
                message=(
                    f"RiskEngineConfig.scoring must be ScoringConfig, "
                    f"got {type(self.scoring).__name__}."
                ),
                field="scoring",
                value=self.scoring,
            )
        if not isinstance(self.thresholds, ThresholdConfig):
            raise RiskEngineConfigurationError(
                message=(
                    f"RiskEngineConfig.thresholds must be ThresholdConfig, "
                    f"got {type(self.thresholds).__name__}."
                ),
                field="thresholds",
                value=self.thresholds,
            )
        if not isinstance(self.confidence, ConfidenceConfig):
            raise RiskEngineConfigurationError(
                message=(
                    f"RiskEngineConfig.confidence must be ConfidenceConfig, "
                    f"got {type(self.confidence).__name__}."
                ),
                field="confidence",
                value=self.confidence,
            )
        if not isinstance(self.aggregation, AggregationConfig):
            raise RiskEngineConfigurationError(
                message=(
                    f"RiskEngineConfig.aggregation must be AggregationConfig, "
                    f"got {type(self.aggregation).__name__}."
                ),
                field="aggregation",
                value=self.aggregation,
            )
        if not isinstance(self.policy_mapping, PolicyMappingConfig):
            raise RiskEngineConfigurationError(
                message=(
                    f"RiskEngineConfig.policy_mapping must be PolicyMappingConfig, "
                    f"got {type(self.policy_mapping).__name__}."
                ),
                field="policy_mapping",
                value=self.policy_mapping,
            )
        if not isinstance(self.adaptive, AdaptiveConfig):
            raise RiskEngineConfigurationError(
                message=(
                    f"RiskEngineConfig.adaptive must be AdaptiveConfig, "
                    f"got {type(self.adaptive).__name__}."
                ),
                field="adaptive",
                value=self.adaptive,
            )