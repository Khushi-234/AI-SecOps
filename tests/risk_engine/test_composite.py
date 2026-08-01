"""
Unit tests for risk_engine.scoring.composite — Sprint 7 Verification Phase.

Tests public orchestration behavior of CompositeScorer:
    - Dependency injection of sub-strategy scorers (WeightedScorer, ThresholdScorer, AdaptiveScorer)
    - Strategy invocation verification (call count, parameters passed)
    - Full RiskScore result model verification (raw_score, normalized_score, scoring_strategy, weight, confidence, metadata)
    - Combination algorithm correctness across multiple strategy outputs
    - Independent fail-secure error propagation for each sub-strategy
    - Structural and numeric input validation (InvalidRiskInputError)
    - Deterministic execution repeatability with fixed timestamps
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Mapping
from unittest.mock import MagicMock
import pytest

from risk_engine.base_scorer import BaseScorer
from risk_engine.exceptions import InvalidRiskInputError, RiskEngineExecutionError
from risk_engine.models import RiskEvidence, RiskScore
from risk_engine.scoring.composite import CompositeScorer

#: Deterministic UTC timestamp for unit test fixtures
FIXED_TIMESTAMP: datetime = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture
def mock_weighted_scorer() -> MagicMock:
    """Provide a mock WeightedScorer instance."""
    scorer = MagicMock(spec=BaseScorer)
    scorer.score.return_value = RiskScore(
        scoring_strategy="WeightedScorer",
        raw_score=0.80,
        normalized_score=0.80,
        weight=1.0,
        confidence=1.0,
    )
    return scorer


@pytest.fixture
def mock_threshold_scorer() -> MagicMock:
    """Provide a mock ThresholdScorer instance."""
    scorer = MagicMock(spec=BaseScorer)
    scorer.score.return_value = RiskScore(
        scoring_strategy="ThresholdScorer",
        raw_score=0.70,
        normalized_score=0.70,
        weight=1.0,
        confidence=1.0,
    )
    return scorer


@pytest.fixture
def mock_adaptive_scorer() -> MagicMock:
    """Provide a mock AdaptiveScorer instance."""
    scorer = MagicMock(spec=BaseScorer)
    scorer.score.return_value = RiskScore(
        scoring_strategy="AdaptiveScorer",
        raw_score=0.60,
        normalized_score=0.60,
        weight=1.0,
        confidence=1.0,
    )
    return scorer


@pytest.fixture
def composite_scorer(
    mock_weighted_scorer: MagicMock,
    mock_threshold_scorer: MagicMock,
    mock_adaptive_scorer: MagicMock,
) -> CompositeScorer:
    """Provide a CompositeScorer instance injected with mock sub-scorers."""
    return CompositeScorer(
        weighted_scorer=mock_weighted_scorer,
        threshold_scorer=mock_threshold_scorer,
        adaptive_scorer=mock_adaptive_scorer,
    )


@pytest.fixture
def sample_evidence() -> RiskEvidence:
    """Provide a canonical RiskEvidence fixture with a deterministic timestamp."""
    return RiskEvidence(
        evidence_id="ev-comp-1",
        source_module="PROMPT_FIREWALL",
        detector_name="JailbreakDetector",
        finding_type="JAILBREAK",
        severity="HIGH",
        confidence=0.90,
        risk_score=0.50,
        description="Sample finding for composite scoring",
        timestamp=FIXED_TIMESTAMP,
    )


# =============================================================================
# 1. Initialization Tests
# =============================================================================


def test_composite_scorer_initialization(composite_scorer: CompositeScorer):
    """Verify CompositeScorer initializes properly with injected sub-scorers."""
    # Assert
    assert isinstance(composite_scorer, CompositeScorer)


# =============================================================================
# 2. Dependency Interaction & Orchestration Verification Tests
# =============================================================================


def test_composite_scorer_orchestrates_all_sub_scorers(
    composite_scorer: CompositeScorer,
    mock_weighted_scorer: MagicMock,
    mock_threshold_scorer: MagicMock,
    mock_adaptive_scorer: MagicMock,
    sample_evidence: RiskEvidence,
):
    """Verify CompositeScorer invokes score() on each injected sub-scorer exactly once with expected inputs."""
    # Arrange
    evidence_list = [sample_evidence]

    # Act
    result = composite_scorer.score(evidence_list)

    # Assert
    assert isinstance(result, RiskScore)
    mock_weighted_scorer.score.assert_called_once_with(evidence_list)
    mock_threshold_scorer.score.assert_called_once_with(evidence_list)
    mock_adaptive_scorer.score.assert_called_once_with(evidence_list)


# =============================================================================
# 3. Complete RiskScore Result Model Verification Tests
# =============================================================================


def test_composite_scorer_verifies_full_risk_score_model(
    composite_scorer: CompositeScorer, sample_evidence: RiskEvidence
):
    """Verify complete RiskScore object attributes (scoring_strategy, raw_score, normalized_score, weight, confidence, metadata)."""
    # Act
    result = composite_scorer.score([sample_evidence])

    # Assert: 0.80 * 0.4 + 0.70 * 0.3 + 0.60 * 0.3 = 0.32 + 0.21 + 0.18 = 0.71
    assert result.scoring_strategy == "CompositeScorer"
    assert result.raw_score == pytest.approx(0.71)
    assert result.normalized_score == pytest.approx(0.71)
    assert result.confidence == 1.0
    assert result.weight == 1.0
    assert isinstance(result.metadata, Mapping)
    assert result.metadata.get("scorer_class") == "CompositeScorer"
    assert result.metadata.get("evidence_count") == 1


# =============================================================================
# 4. Boundary & Clamping Tests
# =============================================================================


def test_composite_scorer_zero_scores(
    mock_weighted_scorer: MagicMock,
    mock_threshold_scorer: MagicMock,
    mock_adaptive_scorer: MagicMock,
    sample_evidence: RiskEvidence,
):
    """Verify composite score evaluates to 0.0 when all sub-scorers return 0.0."""
    # Arrange
    zero_score = RiskScore(
        scoring_strategy="ZeroScorer", raw_score=0.0, normalized_score=0.0, weight=1.0, confidence=1.0
    )
    mock_weighted_scorer.score.return_value = zero_score
    mock_threshold_scorer.score.return_value = zero_score
    mock_adaptive_scorer.score.return_value = zero_score

    scorer = CompositeScorer(
        weighted_scorer=mock_weighted_scorer,
        threshold_scorer=mock_threshold_scorer,
        adaptive_scorer=mock_adaptive_scorer,
    )

    # Act
    result = scorer.score([sample_evidence])

    # Assert
    assert result.raw_score == 0.0
    assert result.normalized_score == 0.0
    assert result.confidence == 1.0
    assert result.weight == 1.0


def test_composite_scorer_max_scores(
    mock_weighted_scorer: MagicMock,
    mock_threshold_scorer: MagicMock,
    mock_adaptive_scorer: MagicMock,
    sample_evidence: RiskEvidence,
):
    """Verify composite score evaluates to 1.0 when all sub-scorers return 1.0."""
    # Arrange
    max_score = RiskScore(
        scoring_strategy="MaxScorer", raw_score=1.0, normalized_score=1.0, weight=1.0, confidence=1.0
    )
    mock_weighted_scorer.score.return_value = max_score
    mock_threshold_scorer.score.return_value = max_score
    mock_adaptive_scorer.score.return_value = max_score

    scorer = CompositeScorer(
        weighted_scorer=mock_weighted_scorer,
        threshold_scorer=mock_threshold_scorer,
        adaptive_scorer=mock_adaptive_scorer,
    )

    # Act
    result = scorer.score([sample_evidence])

    # Assert
    assert result.raw_score == 1.0
    assert result.normalized_score == 1.0
    assert result.confidence == 1.0
    assert result.weight == 1.0


# =============================================================================
# 5. Independent Sub-Scorer Fail-Secure Tests
# =============================================================================


def test_composite_scorer_weighted_scorer_failure_raises_execution_error(
    mock_weighted_scorer: MagicMock,
    mock_threshold_scorer: MagicMock,
    mock_adaptive_scorer: MagicMock,
    sample_evidence: RiskEvidence,
):
    """Independently verify WeightedScorer failure raises RiskEngineExecutionError."""
    # Arrange
    mock_weighted_scorer.score.side_effect = RuntimeError("WeightedScorer internal error")

    scorer = CompositeScorer(
        weighted_scorer=mock_weighted_scorer,
        threshold_scorer=mock_threshold_scorer,
        adaptive_scorer=mock_adaptive_scorer,
    )

    # Act & Assert
    with pytest.raises(RiskEngineExecutionError) as exc_info:
        scorer.score([sample_evidence])
    assert "WeightedScorer" in str(exc_info.value) or "RuntimeError" in str(exc_info.value)


def test_composite_scorer_threshold_scorer_failure_raises_execution_error(
    mock_weighted_scorer: MagicMock,
    mock_threshold_scorer: MagicMock,
    mock_adaptive_scorer: MagicMock,
    sample_evidence: RiskEvidence,
):
    """Independently verify ThresholdScorer failure raises RiskEngineExecutionError."""
    # Arrange
    mock_threshold_scorer.score.side_effect = RuntimeError("ThresholdScorer internal error")

    scorer = CompositeScorer(
        weighted_scorer=mock_weighted_scorer,
        threshold_scorer=mock_threshold_scorer,
        adaptive_scorer=mock_adaptive_scorer,
    )

    # Act & Assert
    with pytest.raises(RiskEngineExecutionError) as exc_info:
        scorer.score([sample_evidence])
    assert "ThresholdScorer" in str(exc_info.value) or "RuntimeError" in str(exc_info.value)


def test_composite_scorer_adaptive_scorer_failure_raises_execution_error(
    mock_weighted_scorer: MagicMock,
    mock_threshold_scorer: MagicMock,
    mock_adaptive_scorer: MagicMock,
    sample_evidence: RiskEvidence,
):
    """Independently verify AdaptiveScorer failure raises RiskEngineExecutionError."""
    # Arrange
    mock_adaptive_scorer.score.side_effect = RuntimeError("AdaptiveScorer internal error")

    scorer = CompositeScorer(
        weighted_scorer=mock_weighted_scorer,
        threshold_scorer=mock_threshold_scorer,
        adaptive_scorer=mock_adaptive_scorer,
    )

    # Act & Assert
    with pytest.raises(RiskEngineExecutionError) as exc_info:
        scorer.score([sample_evidence])
    assert "AdaptiveScorer" in str(exc_info.value) or "RuntimeError" in str(exc_info.value)


# =============================================================================
# 6. Input Validation & Negative Tests
# =============================================================================


def test_composite_scorer_empty_evidence_raises_invalid_input(composite_scorer: CompositeScorer):
    """Verify scoring an empty evidence collection raises InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        composite_scorer.score([])
    assert "cannot be empty" in exc_info.value.message


def test_composite_scorer_none_evidence_raises_invalid_input(composite_scorer: CompositeScorer):
    """Verify scoring None raises InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        composite_scorer.score(None)  # type: ignore[arg-type]
    assert "cannot be empty" in exc_info.value.message


def test_composite_scorer_invalid_evidence_type_raises_invalid_input(composite_scorer: CompositeScorer):
    """Verify scoring non-RiskEvidence objects raises InvalidRiskInputError."""
    # Act & Assert
    with pytest.raises(InvalidRiskInputError) as exc_info:
        composite_scorer.score(["invalid_object"])  # type: ignore[arg-type]
    assert "not a RiskEvidence instance" in exc_info.value.message


# =============================================================================
# 7. Deterministic Execution Repeatability Tests
# =============================================================================


def test_composite_scorer_deterministic_repeatability(
    composite_scorer: CompositeScorer, sample_evidence: RiskEvidence
):
    """Verify multiple score evaluations produce identical composite scores."""
    # Act
    res1 = composite_scorer.score([sample_evidence])
    res2 = composite_scorer.score([sample_evidence])

    # Assert
    assert res1.raw_score == res2.raw_score
    assert res1.normalized_score == res2.normalized_score
    assert res1.scoring_strategy == res2.scoring_strategy
    assert res1.confidence == res2.confidence
    assert res1.weight == res2.weight
