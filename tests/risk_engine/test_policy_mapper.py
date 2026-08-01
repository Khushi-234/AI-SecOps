"""
Unit tests for risk_engine.policy_mapper — Sprint 7 Verification Phase.

Tests public behavior of PolicyMapper:
    - RiskLevel classification (LOW, MEDIUM, HIGH, CRITICAL)
    - Confidence-aware action dispatch (ALLOW, ALLOW_WITH_MONITORING, ALLOW_WITH_WARNING, REVIEW, ESCALATE, BLOCK)
    - Boundary condition evaluation (0.0, threshold floors, 1.0)
    - Complete RiskRecommendation DTO verification (action, reason, priority, requires_human_review, metadata)
    - Configuration injection and custom threshold boundaries
    - Structurally fail-secure input validation (InvalidRiskInputError)
    - Configuration validation (RiskEngineConfigurationError)
    - Deterministic execution repeatability with fixed timestamps
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Sequence
import pytest

from risk_engine.config import RiskEngineConfig, ThresholdConfig
from risk_engine.enums import RecommendedAction, RiskLevel
from risk_engine.exceptions import InvalidRiskInputError, RiskEngineConfigurationError
from risk_engine.models import RiskEvidence, RiskRecommendation
from risk_engine.policy_mapper import PolicyMapper

#: Deterministic UTC timestamp for unit test fixtures
FIXED_TIMESTAMP: datetime = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture
def mapper() -> PolicyMapper:
    """Provide a default PolicyMapper instance."""
    return PolicyMapper()


@pytest.fixture
def sample_evidence() -> RiskEvidence:
    """Provide a canonical RiskEvidence fixture with a deterministic timestamp."""
    return RiskEvidence(
        evidence_id="ev-policy-1",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.50,
        description="Sample evidence item for policy mapping",
        timestamp=FIXED_TIMESTAMP,
    )


# =============================================================================
# 1. Initialization & Configuration Tests
# =============================================================================


def test_policy_mapper_initialization(mapper: PolicyMapper):
    """Verify PolicyMapper initializes properly with default configuration."""
    # Assert
    assert isinstance(mapper, PolicyMapper)


def test_policy_mapper_custom_config_initialization():
    """Verify PolicyMapper accepts a custom RiskEngineConfig with valid custom thresholds."""
    # Arrange
    custom_cfg = RiskEngineConfig(
        thresholds=ThresholdConfig(low=0.2, medium=0.5, high=0.8, critical=0.95)
    )

    # Act
    mapper = PolicyMapper(config=custom_cfg)
    ev = RiskEvidence(
        evidence_id="ev-custom",
        source_module="INPUT_VALIDATOR",
        detector_name="Det",
        finding_type="TYPE",
        severity="LOW",
        confidence=0.90,
        risk_score=0.15,
        description="Custom config item",
        timestamp=FIXED_TIMESTAMP,
    )
    level, action, _ = mapper.map_policy(0.15, 0.90, [ev])

    # Assert: score 0.15 < low (0.2) -> LOW
    assert level == RiskLevel.LOW
    assert action == RecommendedAction.ALLOW


def test_policy_mapper_invalid_threshold_config_raises_error():
    """Verify initializing PolicyMapper with unordered thresholds raises RiskEngineConfigurationError."""
    # Arrange & Act & Assert: low > medium violates threshold ordering rule
    with pytest.raises(RiskEngineConfigurationError) as exc_info:
        invalid_cfg = RiskEngineConfig(
            thresholds=ThresholdConfig(low=0.8, medium=0.2, high=0.7, critical=0.9)
        )
        PolicyMapper(config=invalid_cfg)
    assert exc_info.value.details.get("field") == "thresholds"



# =============================================================================
# 2. Risk Level Mapping & Confidence Awareness Tests
# =============================================================================


@pytest.mark.parametrize(
    "composite_score, confidence_score, expected_level, expected_action, expected_review",
    [
        # LOW Risk (< 0.1)
        (0.05, 0.90, RiskLevel.LOW, RecommendedAction.ALLOW, False),
        (0.05, 0.30, RiskLevel.LOW, RecommendedAction.ALLOW_WITH_MONITORING, False),
        # MEDIUM Risk (0.1 <= score < 0.4)
        (0.25, 0.90, RiskLevel.MEDIUM, RecommendedAction.ALLOW_WITH_MONITORING, False),
        (0.25, 0.30, RiskLevel.MEDIUM, RecommendedAction.ALLOW_WITH_WARNING, True),
        # HIGH Risk (0.4 <= score < 0.7)
        (0.55, 0.90, RiskLevel.HIGH, RecommendedAction.BLOCK, False),
        (0.55, 0.30, RiskLevel.HIGH, RecommendedAction.REVIEW, True),
        # CRITICAL Risk (score >= 0.7)
        (0.85, 0.90, RiskLevel.CRITICAL, RecommendedAction.BLOCK, False),
        (0.85, 0.30, RiskLevel.CRITICAL, RecommendedAction.ESCALATE, True),
    ],
)
def test_map_policy_levels_and_confidence(
    mapper: PolicyMapper,
    sample_evidence: RiskEvidence,
    composite_score: float,
    confidence_score: float,
    expected_level: RiskLevel,
    expected_action: RecommendedAction,
    expected_review: bool,
):
    """Verify PolicyMapper maps scores and confidence levels to expected RiskLevel and RecommendedAction."""
    # Act
    level, action, recommendation = mapper.map_policy(
        composite_score, confidence_score, [sample_evidence]
    )

    # Assert
    assert level == expected_level
    assert action == expected_action
    assert isinstance(recommendation, RiskRecommendation)
    assert recommendation.action == expected_action
    assert recommendation.requires_human_review == expected_review
    assert isinstance(recommendation.reason, str)
    assert len(recommendation.reason) > 0


# =============================================================================
# 3. Exact Boundary Value Tests
# =============================================================================


@pytest.mark.parametrize(
    "composite_score, expected_level",
    [
        (0.00, RiskLevel.LOW),
        (0.099, RiskLevel.LOW),
        (0.10, RiskLevel.MEDIUM),  # exact low boundary transition -> MEDIUM
        (0.399, RiskLevel.MEDIUM),
        (0.40, RiskLevel.HIGH),  # exact medium boundary transition -> HIGH
        (0.699, RiskLevel.HIGH),
        (0.70, RiskLevel.CRITICAL),  # exact high boundary transition -> CRITICAL
        (1.00, RiskLevel.CRITICAL),
    ],
)
def test_map_policy_boundary_transitions(
    mapper: PolicyMapper, sample_evidence: RiskEvidence, composite_score: float, expected_level: RiskLevel
):
    """Verify exact boundary value score transitions match configured threshold floors."""
    # Act
    level, _, _ = mapper.map_policy(composite_score, 0.90, [sample_evidence])

    # Assert
    assert level == expected_level


# =============================================================================
# 4. Returned DTO Model Correctness Tests
# =============================================================================


def test_map_policy_returns_valid_recommendation_dto(
    mapper: PolicyMapper, sample_evidence: RiskEvidence
):
    """Verify RiskRecommendation DTO exposes valid priority, action, reason, and metadata fields."""
    # Act
    level, action, recommendation = mapper.map_policy(0.85, 0.90, [sample_evidence])

    # Assert
    assert level == RiskLevel.CRITICAL
    assert action == RecommendedAction.BLOCK
    assert isinstance(recommendation, RiskRecommendation)
    assert recommendation.action == RecommendedAction.BLOCK
    assert recommendation.priority == 10  # CRITICAL priority

    assert recommendation.requires_human_review is False
    assert recommendation.metadata.get("risk_level") == RiskLevel.CRITICAL.value
    assert recommendation.metadata.get("composite_score") == 0.85
    assert recommendation.metadata.get("confidence_score") == 0.90
    assert recommendation.metadata.get("evidence_count") == 1


# =============================================================================
# 5. Negative & Fail-Secure Validation Tests
# =============================================================================


@pytest.mark.parametrize(
    "invalid_score, field_name",
    [
        (-0.01, "composite_score"),
        (1.01, "composite_score"),
        (float("nan"), "composite_score"),
        (float("inf"), "composite_score"),
    ],
)
def test_map_policy_invalid_composite_score_raises_error(
    mapper: PolicyMapper, sample_evidence: RiskEvidence, invalid_score: float, field_name: str
):
    """Verify out-of-bound, NaN, or infinite composite scores raise InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        mapper.map_policy(invalid_score, 0.90, [sample_evidence])
    assert exc_info.value.details.get("field") == field_name


@pytest.mark.parametrize(
    "invalid_conf, field_name",
    [
        (-0.01, "confidence_score"),
        (1.01, "confidence_score"),
        (float("nan"), "confidence_score"),
        (float("inf"), "confidence_score"),
    ],
)
def test_map_policy_invalid_confidence_score_raises_error(
    mapper: PolicyMapper, sample_evidence: RiskEvidence, invalid_conf: float, field_name: str
):
    """Verify out-of-bound, NaN, or infinite confidence scores raise InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        mapper.map_policy(0.50, invalid_conf, [sample_evidence])
    assert exc_info.value.details.get("field") == field_name


def test_map_policy_none_evidence_raises_invalid_input(mapper: PolicyMapper):
    """Verify passing None as evidence collection raises InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        mapper.map_policy(0.50, 0.90, None)  # type: ignore[arg-type]
    assert exc_info.value.details.get("field") == "evidence"


def test_map_policy_non_sequence_evidence_raises_invalid_input(mapper: PolicyMapper):
    """Verify passing a non-sequence evidence collection raises InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        mapper.map_policy(0.50, 0.90, 12345)  # type: ignore[arg-type]
    assert exc_info.value.details.get("field") == "evidence"


# =============================================================================
# 6. Deterministic Repeatability Tests
# =============================================================================


def test_map_policy_deterministic_repeatability(
    mapper: PolicyMapper, sample_evidence: RiskEvidence
):
    """Verify multiple map_policy calls with identical inputs produce identical tuples and recommendations."""
    # Act
    lvl1, act1, rec1 = mapper.map_policy(0.55, 0.90, [sample_evidence])
    lvl2, act2, rec2 = mapper.map_policy(0.55, 0.90, [sample_evidence])

    # Assert
    assert lvl1 == lvl2
    assert act1 == act2
    assert rec1.action == rec2.action
    assert rec1.reason == rec2.reason
    assert rec1.priority == rec2.priority
    assert rec1.requires_human_review == rec2.requires_human_review
    assert rec1.metadata == rec2.metadata
