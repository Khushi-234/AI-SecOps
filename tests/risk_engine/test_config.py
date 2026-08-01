"""
Unit tests for risk_engine.config — Sprint 7 Verification Phase.

Tests public configuration behavior of RiskEngineConfig and sub-configurations:
    - Default configuration initialization, type assertions, and range verification
    - Custom configuration injection across all sub-config modules
    - Positive boundary value validation (minimum precision, extreme scores 0.0/1.0, factor bounds 0.0/2.0)
    - Negative numeric range and boundary validation (RiskEngineConfigurationError)
    - Unordered threshold validation (low <= medium <= high <= critical)
    - Strategy string validation
    - Dataclass immutability (frozen=True) enforcement
    - Value equality and deterministic repeatability
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from typing import Any
import pytest

from risk_engine.config import (
    AdaptiveConfig,
    AggregationConfig,
    ConfidenceConfig,
    PolicyMappingConfig,
    RiskEngineConfig,
    ScoringConfig,
    ThresholdConfig,
)
from risk_engine.exceptions import RiskEngineConfigurationError


# =============================================================================
# 1. Default Configuration Initialization Tests
# =============================================================================


def test_risk_engine_config_default_initialization():
    """Verify default RiskEngineConfig initializes with valid, populated sub-configs adhering to public types and ranges."""
    # Act
    config = RiskEngineConfig()

    # Assert sub-config types
    assert isinstance(config.scoring, ScoringConfig)
    assert isinstance(config.thresholds, ThresholdConfig)
    assert isinstance(config.confidence, ConfidenceConfig)
    assert isinstance(config.aggregation, AggregationConfig)
    assert isinstance(config.policy_mapping, PolicyMappingConfig)
    assert isinstance(config.adaptive, AdaptiveConfig)

    # Assert contract properties and valid ranges
    assert isinstance(config.scoring.precision, int)
    assert config.scoring.precision > 0
    assert 0.0 <= config.thresholds.low <= config.thresholds.medium <= config.thresholds.high <= config.thresholds.critical <= 1.0
    assert 0.0 <= config.confidence.default_confidence <= 1.0
    assert isinstance(config.aggregation.strategy, str)
    assert isinstance(config.policy_mapping.enabled, bool)
    assert config.adaptive.default_factor > 0.0


# =============================================================================
# 2. Custom Configuration Injection Tests
# =============================================================================


def test_risk_engine_config_custom_initialization():
    """Verify RiskEngineConfig accepts custom sub-configurations."""
    # Arrange
    custom_scoring = ScoringConfig(precision=2, min_score=0.1, max_score=0.9)
    custom_thresholds = ThresholdConfig(low=0.2, medium=0.5, high=0.7, critical=0.85)
    custom_confidence = ConfidenceConfig(default_confidence=0.7, min_confidence=0.1, max_confidence=0.9)
    custom_aggregation = AggregationConfig(strategy="median", min_sources=2, outlier_threshold=1.5)
    custom_policy = PolicyMappingConfig(enabled=True, strict_mode=True)
    custom_adaptive = AdaptiveConfig(
        default_factor=0.9,
        detector_factors={"JailbreakDetector": 1.4},
        finding_type_factors={"JAILBREAK": 1.2},
    )

    # Act
    config = RiskEngineConfig(
        scoring=custom_scoring,
        thresholds=custom_thresholds,
        confidence=custom_confidence,
        aggregation=custom_aggregation,
        policy_mapping=custom_policy,
        adaptive=custom_adaptive,
    )

    # Assert
    assert config.scoring.precision == 2
    assert config.thresholds.medium == 0.5
    assert config.confidence.default_confidence == 0.7
    assert config.aggregation.strategy == "median"
    assert config.policy_mapping.strict_mode is True
    assert config.adaptive.detector_factors.get("JailbreakDetector") == 1.4


# =============================================================================
# 3. Positive Boundary Condition Tests
# =============================================================================


def test_scoring_config_valid_boundary_values():
    """Verify ScoringConfig accepts minimum precision (1) and extreme score boundaries (0.0, 1.0)."""
    # Act
    config = ScoringConfig(precision=1, min_score=0.0, max_score=1.0)

    # Assert
    assert config.precision == 1
    assert config.min_score == 0.0
    assert config.max_score == 1.0


@pytest.mark.parametrize(
    "low, medium, high, critical",
    [
        (0.0, 0.0, 0.0, 0.0),  # minimum floor boundary
        (1.0, 1.0, 1.0, 1.0),  # maximum ceiling boundary
        (0.25, 0.25, 0.50, 0.50),  # equal adjacent thresholds
    ],
)
def test_threshold_config_valid_boundary_values(
    low: float, medium: float, high: float, critical: float
):
    """Verify ThresholdConfig accepts extreme boundary values and equal threshold levels."""
    # Act
    config = ThresholdConfig(low=low, medium=medium, high=high, critical=critical)

    # Assert
    assert config.low == low
    assert config.medium == medium
    assert config.high == high
    assert config.critical == critical


def test_adaptive_config_valid_boundary_values():
    """Verify AdaptiveConfig accepts minimum (0.0) and maximum (2.0) factor boundary limits."""
    # Act
    config = AdaptiveConfig(
        detector_factors={"ZeroFactor": 0.0, "MaxFactor": 2.0},
        default_factor=0.001,
    )

    # Assert
    assert config.detector_factors.get("ZeroFactor") == 0.0
    assert config.detector_factors.get("MaxFactor") == 2.0
    assert config.default_factor == 0.001


# =============================================================================
# 4. Sub-Configuration Validation Tests (Negative Scenarios)
# =============================================================================


@pytest.mark.parametrize("invalid_precision", [0, -1, -5])
def test_scoring_config_non_positive_precision_raises_error(invalid_precision: int):
    """Verify non-positive precision raises RiskEngineConfigurationError."""
    # Act & Assert
    with pytest.raises(RiskEngineConfigurationError) as exc_info:
        ScoringConfig(precision=invalid_precision)
    assert exc_info.value.details.get("field") == "scoring.precision"


def test_scoring_config_min_greater_than_max_raises_error():
    """Verify min_score exceeding max_score raises RiskEngineConfigurationError."""
    # Act & Assert
    with pytest.raises(RiskEngineConfigurationError) as exc_info:
        ScoringConfig(min_score=0.8, max_score=0.2)
    assert exc_info.value.details.get("field") == "scoring.min_score"


@pytest.mark.parametrize(
    "low, medium, high, critical",
    [
        (0.5, 0.4, 0.7, 0.9),  # low > medium
        (0.1, 0.8, 0.7, 0.9),  # medium > high
        (0.1, 0.4, 0.95, 0.9),  # high > critical
    ],
)
def test_threshold_config_unordered_thresholds_raises_error(
    low: float, medium: float, high: float, critical: float
):
    """Verify unordered threshold levels raise RiskEngineConfigurationError."""
    # Act & Assert
    with pytest.raises(RiskEngineConfigurationError) as exc_info:
        ThresholdConfig(low=low, medium=medium, high=high, critical=critical)
    assert exc_info.value.details.get("field") == "thresholds"


def test_confidence_config_min_exceeding_max_raises_error():
    """Verify min_confidence exceeding max_confidence raises RiskEngineConfigurationError."""
    # Act & Assert
    with pytest.raises(RiskEngineConfigurationError) as exc_info:
        ConfidenceConfig(min_confidence=0.9, max_confidence=0.1)
    assert exc_info.value.details.get("field") == "confidence.min_confidence"


def test_aggregation_config_invalid_strategy_raises_error():
    """Verify an invalid aggregation strategy string raises RiskEngineConfigurationError."""
    # Act & Assert
    with pytest.raises(RiskEngineConfigurationError) as exc_info:
        AggregationConfig(strategy="unsupported_strategy")
    assert exc_info.value.details.get("field") == "aggregation.strategy"


@pytest.mark.parametrize("invalid_enabled", ["true", 1, None])
def test_policy_mapping_config_non_bool_enabled_raises_error(invalid_enabled: Any):
    """Verify non-boolean enabled parameter raises RiskEngineConfigurationError."""
    # Act & Assert
    with pytest.raises(RiskEngineConfigurationError) as exc_info:
        PolicyMappingConfig(enabled=invalid_enabled)  # type: ignore[arg-type]
    assert exc_info.value.details.get("field") == "policy_mapping.enabled"


def test_adaptive_config_out_of_bounds_factor_raises_error():
    """Verify factor values exceeding 2.0 raise RiskEngineConfigurationError."""
    # Act & Assert
    with pytest.raises(RiskEngineConfigurationError) as exc_info:
        AdaptiveConfig(detector_factors={"ExtremeDetector": 3.5})
    assert "adaptive.detector_factors" in str(exc_info.value.details.get("field", ""))


def test_root_config_invalid_subconfig_type_raises_error():
    """Verify passing non-dataclass objects to RiskEngineConfig raises RiskEngineConfigurationError."""
    # Act & Assert
    with pytest.raises(RiskEngineConfigurationError) as exc_info:
        RiskEngineConfig(scoring="not_a_scoring_config")  # type: ignore[arg-type]
    assert exc_info.value.details.get("field") == "scoring"


# =============================================================================
# 5. Immutability & Equality Tests
# =============================================================================


def test_config_dataclass_immutability():
    """Verify modifying fields on frozen configuration dataclasses raises FrozenInstanceError or AttributeError."""
    # Arrange
    config = RiskEngineConfig()

    # Act & Assert
    with pytest.raises((FrozenInstanceError, AttributeError)):
        config.scoring = ScoringConfig()  # type: ignore[misc]


def test_config_equality_and_value_comparison():
    """Verify two identically initialized configuration instances compare as equal."""
    # Arrange
    cfg1 = RiskEngineConfig()
    cfg2 = RiskEngineConfig()

    # Assert
    assert cfg1 == cfg2


# =============================================================================
# 6. Deterministic Repeatability Tests
# =============================================================================


def test_config_deterministic_repeatability():
    """Verify creating configuration instances repeatedly produces identical attribute values."""
    # Act
    c1 = RiskEngineConfig()
    c2 = RiskEngineConfig()

    # Assert
    assert c1.scoring.precision == c2.scoring.precision
    assert c1.thresholds.critical == c2.thresholds.critical
    assert c1.confidence.default_confidence == c2.confidence.default_confidence
    assert c1.aggregation.strategy == c2.aggregation.strategy
    assert c1.policy_mapping.enabled == c2.policy_mapping.enabled
    assert c1.adaptive.default_factor == c2.adaptive.default_factor
