"""
Centralized Configuration Module for the Risk Engine — Sprint 7.

Provides immutable, memory-efficient configuration structures governing scoring strategies,
risk thresholds, confidence calculations, multi-module aggregation rules, and policy mapping.

Design Principles:
    - SOLID: Single responsibility per configuration section model.
    - DRY: Encapsulated validation routines and module constants.
    - Enterprise Pattern: Hierarchical composition with fail-secure validation.
    - Thread Safety: Implemented using frozen dataclasses (`frozen=True`, `slots=True`),
      rendering all configuration instances completely immutable and thread-safe for
      concurrent multi-threaded evaluation pipelines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

try:
    from risk_engine.exceptions import RiskEngineConfigurationError
except (ImportError, AttributeError):

    class RiskEngineConfigurationError(ValueError):  # type: ignore[no-redef]
        """Exception raised when Risk Engine configuration parameters are invalid."""


# ===========================================================================
# Module Constants (Enterprise Defaults & Constraints)
# ===========================================================================

# Default Threshold Values (Normalized [0.0, 1.0])
DEFAULT_LOW_THRESHOLD: float = 0.30
DEFAULT_MEDIUM_THRESHOLD: float = 0.60
DEFAULT_HIGH_THRESHOLD: float = 0.85
DEFAULT_CRITICAL_THRESHOLD: float = 1.00

# Default Scoring Component Weights
DEFAULT_WEIGHT_FIREWALL: float = 0.55
DEFAULT_WEIGHT_VALIDATION: float = 0.25
DEFAULT_WEIGHT_HISTORICAL: float = 0.10
DEFAULT_WEIGHT_CONTEXT: float = 0.10

# Default Confidence Weights
DEFAULT_MINIMUM_CONFIDENCE: float = 0.0
DEFAULT_HISTORICAL_CONFIDENCE_WEIGHT: float = 0.20
DEFAULT_DETECTOR_CONFIDENCE_WEIGHT: float = 0.50
DEFAULT_VALIDATOR_CONFIDENCE_WEIGHT: float = 0.30

# Strategy and Action Option Constraints
VALID_SCORING_STRATEGIES: tuple[str, ...] = (
    "composite",
    "weighted",
    "threshold",
    "adaptive",
)
VALID_AGGREGATION_STRATEGIES: tuple[str, ...] = (
    "max_severity_diminishing_sum",
    "weighted_average",
    "strict_max",
)
VALID_MERGE_STRATEGIES: tuple[str, ...] = (
    "deduplicate_highest_severity",
    "union_all",
    "intersection",
)
VALID_FAIL_SAFE_BEHAVIOURS: tuple[str, ...] = (
    "fail_secure",
    "fail_open",
    "degraded_eval",
)
VALID_POLICY_ACTIONS: tuple[str, ...] = (
    "ALLOW",
    "MONITOR",
    "SANITIZE_RECOMMENDED",
    "ESCALATE",
    "BLOCK",
)

FLOAT_TOLERANCE: float = 1e-5


# ===========================================================================
# Internal Helper Validation Functions
# ===========================================================================


def _validate_normalized_float(value: float, name: str) -> None:
    """Validates that a floating point value lies within the normalized range [0.0, 1.0]."""
    if not (0.0 <= value <= 1.0):
        raise RiskEngineConfigurationError(
            f"Configuration error: '{name}' must be a normalized float between 0.0 and 1.0, got {value}"
        )


def _validate_choice(value: str, name: str, valid_choices: tuple[str, ...]) -> None:
    """Validates that a string parameter is present in the specified allowed choices."""
    if value not in valid_choices:
        raise RiskEngineConfigurationError(
            f"Configuration error: '{name}' must be one of {valid_choices}, got '{value}'"
        )


# ===========================================================================
# Configuration Sections
# ===========================================================================


@dataclass(slots=True, frozen=True)
class ScoringConfig:
    """
    Configuration parameters governing risk scoring execution.

    Attributes:
        default_scoring_strategy: Primary strategy name ('composite', 'weighted', 'threshold', 'adaptive').
        enable_weighted_scoring: Enables feature-weighted linear score calculation.
        enable_threshold_scoring: Enables hard rule threshold score floor overrides.
        enable_adaptive_scoring: Enables historical reputation and context score adjustments.
        score_normalization: Enforces normalization of final composite score to [0.0, 1.0].
        default_weights: Mapping of component names to feature weights.
    """

    default_scoring_strategy: str = "composite"
    enable_weighted_scoring: bool = True
    enable_threshold_scoring: bool = True
    enable_adaptive_scoring: bool = True
    score_normalization: bool = True
    default_weights: Mapping[str, float] = field(
        default_factory=lambda: {
            "firewall": DEFAULT_WEIGHT_FIREWALL,
            "validation": DEFAULT_WEIGHT_VALIDATION,
            "historical": DEFAULT_WEIGHT_HISTORICAL,
            "context": DEFAULT_WEIGHT_CONTEXT,
        }
    )

    def __post_init__(self) -> None:
        """Validates scoring configuration boundaries and weights."""
        _validate_choice(
            self.default_scoring_strategy,
            "default_scoring_strategy",
            VALID_SCORING_STRATEGIES,
        )

        total_weight: float = 0.0
        for component, w_val in self.default_weights.items():
            _validate_normalized_float(w_val, f"default_weights['{component}']")
            total_weight += w_val

        if self.score_normalization and abs(total_weight - 1.0) > FLOAT_TOLERANCE:
            raise RiskEngineConfigurationError(
                f"Configuration error: 'default_weights' must sum to 1.0 when normalization is enabled, "
                f"got total weight {total_weight:.4f}"
            )


@dataclass(slots=True, frozen=True)
class ThresholdConfig:
    """
    Configuration parameters defining strict classification boundaries for risk levels.

    Validation Rule:
        Must strictly follow ordered boundaries: 0.0 <= low < medium < high <= critical <= 1.0.

    Attributes:
        low_threshold: Upper score limit for LOW risk tier.
        medium_threshold: Upper score limit for MEDIUM risk tier.
        high_threshold: Upper score limit for HIGH risk tier.
        critical_threshold: Ceiling limit for CRITICAL risk tier.
    """

    low_threshold: float = DEFAULT_LOW_THRESHOLD
    medium_threshold: float = DEFAULT_MEDIUM_THRESHOLD
    high_threshold: float = DEFAULT_HIGH_THRESHOLD
    critical_threshold: float = DEFAULT_CRITICAL_THRESHOLD

    def __post_init__(self) -> None:
        """Validates threshold order and range boundaries."""
        _validate_normalized_float(self.low_threshold, "low_threshold")
        _validate_normalized_float(self.medium_threshold, "medium_threshold")
        _validate_normalized_float(self.high_threshold, "high_threshold")
        _validate_normalized_float(self.critical_threshold, "critical_threshold")

        if not (
            0.0
            <= self.low_threshold
            < self.medium_threshold
            < self.high_threshold
            <= self.critical_threshold
            <= 1.0
        ):
            raise RiskEngineConfigurationError(
                "Configuration error: Risk thresholds must strictly satisfy ordering: "
                "0.0 <= LOW < MEDIUM < HIGH <= CRITICAL <= 1.0. Got: "
                f"LOW={self.low_threshold}, MEDIUM={self.medium_threshold}, "
                f"HIGH={self.high_threshold}, CRITICAL={self.critical_threshold}"
            )


@dataclass(slots=True, frozen=True)
class ConfidenceConfig:
    """
    Configuration settings governing risk assessment confidence calculations.

    Attributes:
        confidence_enabled: Enables mathematical confidence calculation.
        minimum_confidence: Baseline confidence floor [0.0, 1.0].
        historical_confidence_weight: Weight assigned to historical precision factor.
        detector_confidence_weight: Weight assigned to detector signal confidence.
        validator_confidence_weight: Weight assigned to structural validation confidence.
        confidence_normalization: Enforces normalization of confidence metrics to [0.0, 1.0].
    """

    confidence_enabled: bool = True
    minimum_confidence: float = DEFAULT_MINIMUM_CONFIDENCE
    historical_confidence_weight: float = DEFAULT_HISTORICAL_CONFIDENCE_WEIGHT
    detector_confidence_weight: float = DEFAULT_DETECTOR_CONFIDENCE_WEIGHT
    validator_confidence_weight: float = DEFAULT_VALIDATOR_CONFIDENCE_WEIGHT
    confidence_normalization: bool = True

    def __post_init__(self) -> None:
        """Validates confidence bounds and component weights."""
        _validate_normalized_float(self.minimum_confidence, "minimum_confidence")
        _validate_normalized_float(
            self.historical_confidence_weight, "historical_confidence_weight"
        )
        _validate_normalized_float(
            self.detector_confidence_weight, "detector_confidence_weight"
        )
        _validate_normalized_float(
            self.validator_confidence_weight, "validator_confidence_weight"
        )

        if self.confidence_enabled and self.confidence_normalization:
            sum_weights = (
                self.historical_confidence_weight
                + self.detector_confidence_weight
                + self.validator_confidence_weight
            )
            if abs(sum_weights - 1.0) > FLOAT_TOLERANCE:
                raise RiskEngineConfigurationError(
                    f"Configuration error: Confidence weights must sum to 1.0, got {sum_weights:.4f}"
                )


@dataclass(slots=True, frozen=True)
class AggregationConfig:
    """
    Configuration parameters controlling multi-module finding aggregation and conflict resolution.

    Attributes:
        aggregation_strategy: Strategy name for multi-finding risk calculation.
        merge_strategy: Finding deduplication and conflict resolution strategy.
        fail_safe_behaviour: Fallback behavior on module failure ('fail_secure', 'fail_open', 'degraded_eval').
        telemetry_enabled: Enables collection of detailed audit telemetry.
    """

    aggregation_strategy: str = "max_severity_diminishing_sum"
    merge_strategy: str = "deduplicate_highest_severity"
    fail_safe_behaviour: str = "fail_secure"
    telemetry_enabled: bool = True

    def __post_init__(self) -> None:
        """Validates aggregation strategies and fail-safe settings."""
        _validate_choice(
            self.aggregation_strategy,
            "aggregation_strategy",
            VALID_AGGREGATION_STRATEGIES,
        )
        _validate_choice(
            self.merge_strategy, "merge_strategy", VALID_MERGE_STRATEGIES
        )
        _validate_choice(
            self.fail_safe_behaviour,
            "fail_safe_behaviour",
            VALID_FAIL_SAFE_BEHAVIOURS,
        )


@dataclass(slots=True, frozen=True)
class PolicyMappingConfig:
    """
    Configuration settings governing mapping of risk scores to policy recommendations.

    Attributes:
        default_action: Default policy action on system fallback ('BLOCK', 'ALLOW', etc.).
        allow_mapping_overrides: Enables tenant-specific override rules.
        unknown_risk_behaviour: Policy action when risk level is indeterminate ('BLOCK', 'ESCALATE').
    """

    default_action: str = "BLOCK"
    allow_mapping_overrides: bool = False
    unknown_risk_behaviour: str = "BLOCK"

    def __post_init__(self) -> None:
        """Validates action mapping selections."""
        _validate_choice(
            self.default_action, "default_action", VALID_POLICY_ACTIONS
        )
        _validate_choice(
            self.unknown_risk_behaviour,
            "unknown_risk_behaviour",
            VALID_POLICY_ACTIONS,
        )


# ===========================================================================
# Top-Level Configuration Composition Container
# ===========================================================================


@dataclass(slots=True, frozen=True)
class RiskEngineConfig:
    """
    Top-level composite configuration container for the Risk Engine module.

    Composes all sub-domain configuration models (`ScoringConfig`, `ThresholdConfig`,
    `ConfidenceConfig`, `AggregationConfig`, `PolicyMappingConfig`) into a single
    unified, immutable, thread-safe configuration object.

    Thread Safety:
        Frozen dataclass architecture ensures zero-lock, thread-safe read operations
        across parallel evaluation routines.
    """

    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)
    confidence: ConfidenceConfig = field(default_factory=ConfidenceConfig)
    aggregation: AggregationConfig = field(default_factory=AggregationConfig)
    policy_mapping: PolicyMappingConfig = field(default_factory=PolicyMappingConfig)

    def __post_init__(self) -> None:
        """Validates composition integrity."""
        if not isinstance(self.scoring, ScoringConfig):
            raise RiskEngineConfigurationError(
                "Configuration error: 'scoring' must be an instance of ScoringConfig"
            )
        if not isinstance(self.thresholds, ThresholdConfig):
            raise RiskEngineConfigurationError(
                "Configuration error: 'thresholds' must be an instance of ThresholdConfig"
            )
        if not isinstance(self.confidence, ConfidenceConfig):
            raise RiskEngineConfigurationError(
                "Configuration error: 'confidence' must be an instance of ConfidenceConfig"
            )
        if not isinstance(self.aggregation, AggregationConfig):
            raise RiskEngineConfigurationError(
                "Configuration error: 'aggregation' must be an instance of AggregationConfig"
            )
        if not isinstance(self.policy_mapping, PolicyMappingConfig):
            raise RiskEngineConfigurationError(
                "Configuration error: 'policy_mapping' must be an instance of PolicyMappingConfig"
            )
