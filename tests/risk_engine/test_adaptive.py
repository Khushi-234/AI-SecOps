"""
Unit tests for risk_engine.scoring.adaptive — Sprint 7 Verification Phase.

Tests public behavior of AdaptiveScorer:
    - Adaptive factor resolution order (detector factor -> finding_type factor -> default factor)
    - Configuration-driven behavior (enabling/disabling factor types, custom factor maps)
    - Composite score calculation and normalization/clamping
    - Boundary conditions (0.0 scores, score clamping at 1.0)
    - Complete RiskScore result model verification (scoring_strategy, confidence, weight, metadata)
    - Fail-secure empty and null evidence validation (InvalidRiskInputError)
    - Deterministic execution repeatability with fixed timestamps
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from risk_engine.config import AdaptiveConfig, RiskEngineConfig
from risk_engine.exceptions import InvalidRiskInputError
from risk_engine.models import RiskEvidence, RiskScore
from risk_engine.scoring.adaptive import AdaptiveScorer

#: Deterministic UTC timestamp for unit test fixtures
FIXED_TIMESTAMP: datetime = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture
def default_scorer() -> AdaptiveScorer:
    """Provide a default AdaptiveScorer instance."""
    return AdaptiveScorer()


@pytest.fixture
def custom_scorer() -> AdaptiveScorer:
    """Provide an AdaptiveScorer instance with custom detector and finding type factors."""
    config = RiskEngineConfig(
        adaptive=AdaptiveConfig(
            enable_detector_adjustment=True,
            enable_finding_type_adjustment=True,
            default_factor=0.8,
            detector_factors={"JailbreakDetector": 1.5},
            finding_type_factors={"PROMPT_INJECTION": 1.2},
        )
    )
    return AdaptiveScorer(config=config)


@pytest.fixture
def sample_evidence() -> RiskEvidence:
    """Provide a canonical RiskEvidence fixture with a deterministic timestamp."""
    return RiskEvidence(
        evidence_id="ev-adaptive-1",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.50,
        description="Sample finding for adaptive scoring",
        timestamp=FIXED_TIMESTAMP,
    )


# =============================================================================
# 1. Initialization Tests
# =============================================================================


def test_adaptive_scorer_initialization(default_scorer: AdaptiveScorer):
    """Verify AdaptiveScorer initializes properly as a BaseScorer instance."""
    # Assert
    assert isinstance(default_scorer, AdaptiveScorer)


# =============================================================================
# 2. Score Calculation & Factor Resolution Tests
# =============================================================================


def test_adaptive_scorer_single_finding_default_config(
    default_scorer: AdaptiveScorer, sample_evidence: RiskEvidence
):
    """Verify scoring with default configuration applies default factor (1.0) and builds a valid RiskScore."""
    # Act
    result = default_scorer.score([sample_evidence])

    # Assert
    assert isinstance(result, RiskScore)
    assert result.scoring_strategy == "AdaptiveScorer"
    assert result.raw_score == 0.50
    assert result.normalized_score == 0.50
    assert result.confidence == 1.0
    assert result.weight == 1.0
    assert result.metadata.get("scorer_class") == "AdaptiveScorer"


def test_adaptive_scorer_detector_factor_resolution(custom_scorer: AdaptiveScorer):
    """Verify detector-specific factor override (1.5) is applied when matched."""
    # Arrange: JailbreakDetector mapped to 1.5
    evidence = RiskEvidence(
        evidence_id="ev-det",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.50,
        description="Detector factor test",
        timestamp=FIXED_TIMESTAMP,
    )

    # Act
    result = custom_scorer.score([evidence])

    # Assert: 0.50 * 1.5 = 0.75
    assert result.scoring_strategy == "AdaptiveScorer"
    assert result.raw_score == 0.75
    assert result.normalized_score == 0.75
    assert result.confidence == 1.0
    assert result.weight == 1.0


def test_adaptive_scorer_finding_type_factor_resolution(custom_scorer: AdaptiveScorer):
    """Verify finding_type factor (1.2) is applied when detector is not matched."""
    # Arrange: UnknownDetector, PROMPT_INJECTION mapped to 1.2
    evidence = RiskEvidence(
        evidence_id="ev-type",
        source_module="PROMPT_FIREWALL",
        detector_name="UnknownDetector",
        finding_type="PROMPT_INJECTION",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.50,
        description="Finding type factor test",
        timestamp=FIXED_TIMESTAMP,
    )

    # Act
    result = custom_scorer.score([evidence])

    # Assert: 0.50 * 1.2 = 0.60
    assert result.raw_score == 0.60
    assert result.normalized_score == 0.60
    assert result.confidence == 1.0
    assert result.weight == 1.0


def test_adaptive_scorer_default_factor_fallback(custom_scorer: AdaptiveScorer):
    """Verify default factor fallback (0.8) is applied when neither detector nor finding_type matches."""
    # Arrange: unmatched detector and unmatched finding type
    evidence = RiskEvidence(
        evidence_id="ev-def",
        source_module="INPUT_VALIDATOR",
        detector_name="UnknownDetector",
        finding_type="UNKNOWN_TYPE",
        severity="MEDIUM",
        confidence=0.80,
        risk_score=0.50,
        description="Default fallback test",
        timestamp=FIXED_TIMESTAMP,
    )

    # Act
    result = custom_scorer.score([evidence])

    # Assert: 0.50 * 0.8 = 0.40
    assert result.raw_score == 0.40
    assert result.normalized_score == 0.40
    assert result.confidence == 1.0
    assert result.weight == 1.0


def test_adaptive_scorer_disabled_detector_adjustment():
    """Verify detector factor is ignored when enable_detector_adjustment=False."""
    # Arrange
    config = RiskEngineConfig(
        adaptive=AdaptiveConfig(
            enable_detector_adjustment=False,
            enable_finding_type_adjustment=True,
            default_factor=0.8,
            detector_factors={"JailbreakDetector": 2.0},
            finding_type_factors={"JAILBREAK": 1.2},
        )
    )
    scorer = AdaptiveScorer(config=config)
    evidence = RiskEvidence(
        evidence_id="ev-dis",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.50,
        description="Disabled detector adjustment test",
        timestamp=FIXED_TIMESTAMP,
    )

    # Act
    result = scorer.score([evidence])

    # Assert: skips detector (2.0), uses finding_type (1.2) -> 0.50 * 1.2 = 0.60
    assert result.raw_score == 0.60
    assert result.normalized_score == 0.60
    assert result.confidence == 1.0
    assert result.weight == 1.0


# =============================================================================
# 3. Boundary & Normalization Tests
# =============================================================================


def test_adaptive_scorer_zero_risk_score(custom_scorer: AdaptiveScorer):
    """Verify 0.0 risk score yields 0.0 regardless of adjustment factor."""
    # Arrange
    zero_ev = RiskEvidence(
        evidence_id="ev-zero",
        source_module="INPUT_VALIDATOR",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="INFO",
        confidence=0.50,
        risk_score=0.0,
        description="Zero score item",
        timestamp=FIXED_TIMESTAMP,
    )

    # Act
    result = custom_scorer.score([zero_ev])

    # Assert: 0.0 * 1.5 = 0.0
    assert result.raw_score == 0.0
    assert result.normalized_score == 0.0
    assert result.confidence == 1.0
    assert result.weight == 1.0


def test_adaptive_scorer_max_score_clamping(custom_scorer: AdaptiveScorer):
    """Verify adjusted score exceeding 1.0 is clamped to 1.0 ceiling."""
    # Arrange: 0.8 * 1.5 = 1.20 raw score
    evidence = RiskEvidence(
        evidence_id="ev-clamp",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="CRITICAL",
        confidence=0.95,
        risk_score=0.80,
        description="Clamping test item",
        timestamp=FIXED_TIMESTAMP,
    )

    # Act
    result = custom_scorer.score([evidence])

    # Assert
    assert result.raw_score == pytest.approx(1.20)
    assert result.normalized_score == 1.00
    assert result.confidence == 1.0
    assert result.weight == 1.0


# =============================================================================
# 4. Fail-Secure & Negative Tests
# =============================================================================


def test_adaptive_scorer_empty_evidence_raises_invalid_input(default_scorer: AdaptiveScorer):
    """Verify scoring an empty evidence collection raises InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        default_scorer.score([])
    assert "cannot be empty" in exc_info.value.message


def test_adaptive_scorer_none_evidence_raises_invalid_input(default_scorer: AdaptiveScorer):
    """Verify scoring None raises InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        default_scorer.score(None)  # type: ignore[arg-type]
    assert "cannot be empty" in exc_info.value.message


def test_adaptive_scorer_invalid_evidence_item_raises_invalid_input(default_scorer: AdaptiveScorer):
    """Verify scoring a collection with non-RiskEvidence objects raises InvalidRiskInputError."""
    # Arrange
    invalid_evidence = ["not_a_risk_evidence_object"]

    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        default_scorer.score(invalid_evidence)  # type: ignore[arg-type]
    assert "not a RiskEvidence instance" in exc_info.value.message


# =============================================================================
# 5. Deterministic Execution Repeatability Tests
# =============================================================================


def test_adaptive_scorer_deterministic_repeatability(
    custom_scorer: AdaptiveScorer, sample_evidence: RiskEvidence
):
    """Verify multiple score evaluations produce identical complete RiskScore objects."""
    # Act
    res1 = custom_scorer.score([sample_evidence])
    res2 = custom_scorer.score([sample_evidence])

    # Assert
    assert res1.raw_score == res2.raw_score
    assert res1.normalized_score == res2.normalized_score
    assert res1.scoring_strategy == res2.scoring_strategy
    assert res1.confidence == res2.confidence
    assert res1.weight == res2.weight
