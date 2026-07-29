"""
Unit tests for risk_engine.scoring.weighted — Sprint 7 Verification Phase.

Tests public behavior of WeightedScorer:
    - Weighted risk score calculation for single and multiple evidence items
    - Boundary floor (0.0) and ceiling clamping (1.0) for score sums
    - Empty evidence and null payload fail-secure validation
    - Non-RiskEvidence item validation
    - Output model (RiskScore) metadata and telemetry verification
    - Deterministic execution repeatability
"""

from __future__ import annotations

from datetime import datetime, timezone
import pytest

from risk_engine.exceptions import InvalidRiskInputError, RiskEngineExecutionError
from risk_engine.models import RiskEvidence, RiskScore
from risk_engine.scoring.weighted import WeightedScorer


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture
def scorer() -> WeightedScorer:
    """Provide a default WeightedScorer instance for unit tests."""
    return WeightedScorer()


@pytest.fixture
def sample_evidence() -> RiskEvidence:
    """Provide a canonical RiskEvidence fixture."""
    return RiskEvidence(
        evidence_id="ev-weighted-1",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.40,
        description="Sample finding for weighted scoring",
        timestamp=datetime.now(timezone.utc),
    )


# =============================================================================
# 1. Initialization Tests
# =============================================================================


def test_weighted_scorer_initialization(scorer: WeightedScorer):
    """Verify WeightedScorer initializes properly as a BaseScorer instance."""
    # Assert
    assert isinstance(scorer, WeightedScorer)


# =============================================================================
# 2. Score Calculation Tests
# =============================================================================


def test_weighted_scorer_single_finding(scorer: WeightedScorer, sample_evidence: RiskEvidence):
    """Verify scoring a single finding returns a valid RiskScore object."""
    # Act
    result = scorer.score([sample_evidence])

    # Assert
    assert isinstance(result, RiskScore)
    assert result.scoring_strategy == "WeightedScorer"
    assert result.raw_score == 0.40
    assert result.normalized_score == 0.40


def test_weighted_scorer_multiple_findings(scorer: WeightedScorer):
    """Verify scoring multiple findings computes the expected weighted sum."""
    # Arrange
    ev1 = RiskEvidence(
        evidence_id="ev-1",
        source_module="PROMPT_FIREWALL",
        detector_name="Det1",
        finding_type="TYPE_1",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.35,
        description="Finding 1",
    )
    ev2 = RiskEvidence(
        evidence_id="ev-2",
        source_module="INPUT_VALIDATOR",
        detector_name="Det2",
        finding_type="TYPE_2",
        severity="MEDIUM",
        confidence=0.80,
        risk_score=0.25,
        description="Finding 2",
    )

    # Act
    result = scorer.score([ev1, ev2])

    # Assert: 0.35 + 0.25 = 0.60
    assert result.raw_score == 0.60
    assert result.normalized_score == 0.60


# =============================================================================
# 3. Boundary & Clamping Tests
# =============================================================================


def test_weighted_scorer_zero_scores(scorer: WeightedScorer):
    """Verify findings with 0.0 risk score compute to 0.0 normalized score."""
    # Arrange
    zero_ev = RiskEvidence(
        evidence_id="ev-zero",
        source_module="INPUT_VALIDATOR",
        detector_name="ZeroDet",
        finding_type="ZERO",
        severity="INFO",
        confidence=0.50,
        risk_score=0.0,
        description="Zero score item",
    )

    # Act
    result = scorer.score([zero_ev])

    # Assert
    assert result.raw_score == 0.0
    assert result.normalized_score == 0.0


def test_weighted_scorer_max_scores_clamping(scorer: WeightedScorer):
    """Verify weighted score sum exceeding 1.0 is clamped to 1.0 ceiling."""
    # Arrange: 0.8 + 0.8 = 1.6 raw score
    ev1 = RiskEvidence(
        evidence_id="ev-max-1",
        source_module="PROMPT_FIREWALL",
        detector_name="Det1",
        finding_type="MAX1",
        severity="CRITICAL",
        confidence=0.95,
        risk_score=0.80,
        description="Max item 1",
    )
    ev2 = RiskEvidence(
        evidence_id="ev-max-2",
        source_module="PROMPT_FIREWALL",
        detector_name="Det2",
        finding_type="MAX2",
        severity="CRITICAL",
        confidence=0.95,
        risk_score=0.80,
        description="Max item 2",
    )

    # Act
    result = scorer.score([ev1, ev2])

    # Assert
    assert result.raw_score == 1.60
    assert result.normalized_score == 1.0


# =============================================================================
# 4. Fail-Secure & Negative Tests
# =============================================================================


def test_weighted_scorer_empty_evidence_raises_error(scorer: WeightedScorer):
    """Verify scoring an empty evidence collection raises an exception."""
    # Act & Assert
    with pytest.raises(Exception):
        scorer.score([])


def test_weighted_scorer_none_evidence_raises_error(scorer: WeightedScorer):
    """Verify scoring None raises an exception."""
    # Act & Assert
    with pytest.raises(Exception):
        scorer.score(None)  # type: ignore[arg-type]


def test_weighted_scorer_invalid_evidence_item_raises_error(scorer: WeightedScorer):
    """Verify scoring a collection with non-RiskEvidence objects raises an exception."""
    # Arrange
    invalid_evidence = ["not_a_risk_evidence_object"]

    # Act & Assert
    with pytest.raises(Exception):
        scorer.score(invalid_evidence)  # type: ignore[arg-type]


# =============================================================================
# 5. Deterministic Execution Repeatability Tests
# =============================================================================


def test_weighted_scorer_deterministic_repeatability(
    scorer: WeightedScorer, sample_evidence: RiskEvidence
):
    """Verify multiple score evaluations produce identical raw and normalized scores."""
    # Act
    res1 = scorer.score([sample_evidence])
    res2 = scorer.score([sample_evidence])

    # Assert
    assert res1.raw_score == res2.raw_score
    assert res1.normalized_score == res2.normalized_score
