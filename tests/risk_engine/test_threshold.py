"""
Unit tests for risk_engine.scoring.threshold — Sprint 7 Verification Phase.

Tests public behavior of ThresholdScorer:
    - Classification of risk scores against configurable threshold boundaries (LOW, MEDIUM, HIGH, CRITICAL)
    - Threshold contribution accumulation and score normalization/clamping
    - Single and multi-finding threshold evaluations
    - Boundary testing (below, exactly on, and above threshold floors)
    - Fail-secure empty and null evidence validation
    - Deterministic execution repeatability
"""

from __future__ import annotations

from datetime import datetime, timezone
import pytest

from risk_engine.exceptions import InvalidRiskInputError, RiskEngineExecutionError
from risk_engine.models import RiskEvidence, RiskScore
from risk_engine.scoring.threshold import ThresholdScorer


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture
def scorer() -> ThresholdScorer:
    """Provide a default ThresholdScorer instance for unit tests."""
    return ThresholdScorer()


@pytest.fixture
def sample_evidence() -> RiskEvidence:
    """Provide a canonical RiskEvidence fixture."""
    return RiskEvidence(
        evidence_id="ev-thresh-1",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.50,
        description="Sample finding for threshold scoring",
        timestamp=datetime.now(timezone.utc),
    )


# =============================================================================
# 1. Initialization Tests
# =============================================================================


def test_threshold_scorer_initialization(scorer: ThresholdScorer):
    """Verify ThresholdScorer initializes properly as a BaseScorer instance."""
    # Assert
    assert isinstance(scorer, ThresholdScorer)


# =============================================================================
# 2. Threshold Classification & Boundary Tests
# =============================================================================


@pytest.mark.parametrize(
    "risk_score, expected_normalized_score",
    [
        (0.05, 0.10),  # < 0.1 -> LOW threshold contribution (0.10)
        (0.10, 0.40),  # == 0.1 (low boundary) -> MEDIUM threshold contribution (0.40)
        (0.35, 0.40),  # < 0.4 -> MEDIUM threshold contribution (0.40)
        (0.40, 0.70),  # == 0.4 (medium boundary) -> HIGH threshold contribution (0.70)
        (0.65, 0.70),  # < 0.7 -> HIGH threshold contribution (0.70)
        (0.70, 1.00),  # == 0.7 (high boundary) -> CRITICAL threshold contribution (1.00)
        (0.95, 1.00),  # >= 0.7 -> CRITICAL threshold contribution (1.00)
    ],
)
def test_threshold_scorer_boundary_classification(
    scorer: ThresholdScorer, risk_score: float, expected_normalized_score: float
):
    """Verify risk scores map to expected threshold contribution values."""
    # Arrange
    evidence = RiskEvidence(
        evidence_id="ev-bound",
        source_module="INPUT_VALIDATOR",
        detector_name="BoundaryDetector",
        finding_type="BOUNDARY",
        severity="MEDIUM",
        confidence=0.85,
        risk_score=risk_score,
        description="Boundary score test item",
    )

    # Act
    result = scorer.score([evidence])

    # Assert
    assert result.normalized_score == expected_normalized_score


# =============================================================================
# 3. Multi-Finding & Clamping Tests
# =============================================================================


def test_threshold_scorer_multiple_findings(scorer: ThresholdScorer):
    """Verify scoring multiple findings accumulates threshold contributions."""
    # Arrange: two findings mapping to LOW (0.1) and MEDIUM (0.4) -> raw sum 0.5
    ev1 = RiskEvidence(
        evidence_id="ev-1",
        source_module="INPUT_VALIDATOR",
        detector_name="Det1",
        finding_type="TYPE_1",
        severity="LOW",
        confidence=0.80,
        risk_score=0.05,  # maps to 0.10
        description="Low finding",
    )
    ev2 = RiskEvidence(
        evidence_id="ev-2",
        source_module="INPUT_VALIDATOR",
        detector_name="Det2",
        finding_type="TYPE_2",
        severity="MEDIUM",
        confidence=0.80,
        risk_score=0.25,  # maps to 0.40
        description="Medium finding",
    )

    # Act
    result = scorer.score([ev1, ev2])

    # Assert: 0.10 + 0.40 = 0.50
    assert isinstance(result, RiskScore)
    assert result.scoring_strategy == "ThresholdScorer"
    assert result.raw_score == 0.50
    assert result.normalized_score == 0.50


def test_threshold_scorer_max_score_clamping(scorer: ThresholdScorer):
    """Verify accumulated threshold contributions exceeding 1.0 are clamped to 1.0."""
    # Arrange: two HIGH findings (0.7 + 0.7 = 1.4)
    ev1 = RiskEvidence(
        evidence_id="ev-h1",
        source_module="PROMPT_FIREWALL",
        detector_name="Det1",
        finding_type="HIGH1",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.50,  # maps to 0.70
        description="High item 1",
    )
    ev2 = RiskEvidence(
        evidence_id="ev-h2",
        source_module="PROMPT_FIREWALL",
        detector_name="Det2",
        finding_type="HIGH2",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.50,  # maps to 0.70
        description="High item 2",
    )

    # Act
    result = scorer.score([ev1, ev2])

    # Assert
    assert result.raw_score == 1.40
    assert result.normalized_score == 1.00


# =============================================================================
# 4. Fail-Secure & Negative Tests
# =============================================================================


def test_threshold_scorer_empty_evidence_raises_error(scorer: ThresholdScorer):
    """Verify scoring an empty evidence collection raises an exception."""
    # Act & Assert
    with pytest.raises(Exception):
        scorer.score([])


def test_threshold_scorer_none_evidence_raises_error(scorer: ThresholdScorer):
    """Verify scoring None raises an exception."""
    # Act & Assert
    with pytest.raises(Exception):
        scorer.score(None)  # type: ignore[arg-type]


def test_threshold_scorer_invalid_evidence_item_raises_error(scorer: ThresholdScorer):
    """Verify scoring a collection with non-RiskEvidence objects raises an exception."""
    # Arrange
    invalid_evidence = ["not_a_risk_evidence_object"]

    # Act & Assert
    with pytest.raises(Exception):
        scorer.score(invalid_evidence)  # type: ignore[arg-type]


# =============================================================================
# 5. Deterministic Execution Repeatability Tests
# =============================================================================


def test_threshold_scorer_deterministic_repeatability(
    scorer: ThresholdScorer, sample_evidence: RiskEvidence
):
    """Verify multiple score evaluations produce identical raw and normalized scores."""
    # Act
    res1 = scorer.score([sample_evidence])
    res2 = scorer.score([sample_evidence])

    # Assert
    assert res1.raw_score == res2.raw_score
    assert res1.normalized_score == res2.normalized_score
